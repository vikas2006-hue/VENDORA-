"""Vendora - Flask backend (also serves the website from /static/index.html).

DB: set DATABASE_URL (PostgreSQL, e.g. Render Postgres) -> uses PostgreSQL.
    If DATABASE_URL is not set -> uses a local SQLite file (vendora.db) for testing.
"""
import os
import re
import time
import uuid
import secrets
import sqlite3
import threading
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
USE_PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))
SQLITE_PATH = os.environ.get("SQLITE_PATH", os.path.join(BASE, "vendora.db"))

JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_urlsafe(48)
if not os.environ.get("JWT_SECRET"):
    print("WARNING: JWT_SECRET not set - using a random one (logins reset on every restart).")

app = Flask(__name__, static_folder=os.path.join(BASE, "static"), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

if USE_PG:
    import psycopg2
    import psycopg2.extras


# --------------------------------------------------------------------------- DB
def _connect():
    if USE_PG:
        return psycopg2.connect(DATABASE_URL)
    con = sqlite3.connect(SQLITE_PATH)
    con.row_factory = sqlite3.Row
    return con


def db():
    if "db" not in g:
        g.db = _connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    con = g.pop("db", None)
    if con is not None:
        con.close()


def query(sql, args=(), one=False, commit=False):
    """Run SQL written with ? placeholders. Returns list of dicts (or one dict/None)."""
    con = db()
    if USE_PG:
        sql = sql.replace("?", "%s")
        cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        cur = con.cursor()
    try:
        cur.execute(sql, args)
        rows = [dict(r) for r in cur.fetchall()] if cur.description else []
        if commit:
            con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        cur.close()
    if one:
        return rows[0] if rows else None
    return rows


def init_db():
    pk = "BIGSERIAL PRIMARY KEY" if USE_PG else "INTEGER PRIMARY KEY AUTOINCREMENT"
    stmts = [
        f"""CREATE TABLE IF NOT EXISTS vd_users (
            id {pk}, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, phone TEXT, city TEXT, created_at BIGINT)""",
        """CREATE TABLE IF NOT EXISTS vd_admin (
            id INTEGER PRIMARY KEY, email TEXT NOT NULL, password_hash TEXT NOT NULL)""",
        f"""CREATE TABLE IF NOT EXISTS vd_login_log (
            id {pk}, email TEXT, name TEXT, phone TEXT, kind TEXT, at_time BIGINT)""",
        """CREATE TABLE IF NOT EXISTS vd_listings (
            id VARCHAR(64) PRIMARY KEY, title TEXT NOT NULL, price INTEGER, orig_price INTEGER,
            category TEXT, prod_type TEXT, cond_text TEXT, age_text TEXT, quality INTEGER,
            descr TEXT, img TEXT, img_hash TEXT, owner_email TEXT NOT NULL,
            seller_name TEXT, seller_phone TEXT, seller_city TEXT, created_at BIGINT)""",
    ]
    con = _connect()
    try:
        cur = con.cursor()
        for s in stmts:
            cur.execute(s)
        con.commit()
        cur.close()
    finally:
        con.close()


init_db()


# ----------------------------------------------------------------------- helpers
class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


@app.errorhandler(ApiError)
def _api_error(e):
    return jsonify(error=e.message), e.status


@app.errorhandler(413)
def _too_big(_e):
    return jsonify(error="Image is too large"), 413


@app.errorhandler(404)
def _nf(_e):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found"), 404
    return send_from_directory(app.static_folder, "index.html")


@app.errorhandler(Exception)
def _other(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return jsonify(error=e.description), e.code
    app.logger.exception(e)
    return jsonify(error="Server error"), 500


def now_ms():
    return int(time.time() * 1000)


def clean(v):
    return v.strip() if isinstance(v, str) else ""


def body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "Invalid request")
    return data


EMAIL_RE = re.compile(r"^\S+@\S+\.\S+$")


def valid_phone(p):
    d = re.sub(r"\D", "", clean(p))
    return 10 <= len(d) <= 13


def make_token(email, role):
    t = now_ms() // 1000
    return jwt.encode({"sub": email, "role": role, "iat": t, "exp": t + 12 * 3600},
                      JWT_SECRET, algorithm="HS256")


# ------------------------------------------------------------------ rate limiter
_rl = {}
_rl_lock = threading.Lock()


def rl_check(key):
    with _rl_lock:
        v = _rl.get(key)
        if v and time.time() < v[1]:
            raise ApiError(429, f"Too many attempts. Try again in {int(v[1] - time.time()) + 1}s.")


def rl_fail(key):
    with _rl_lock:
        v = _rl.setdefault(key, [0, 0.0])
        v[0] += 1
        if v[0] >= 5:
            v[0] = 0
            v[1] = time.time() + 30


def rl_ok(key):
    with _rl_lock:
        _rl.pop(key, None)


# -------------------------------------------------------------------- auth filter
OPEN = {"/api/auth/register", "/api/auth/login",
        "/api/admin/status", "/api/admin/setup", "/api/admin/login"}


@app.before_request
def auth_filter():
    path = request.path
    if not path.startswith("/api/") or path in OPEN:
        return None
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        raise ApiError(401, "Login required")
    try:
        c = jwt.decode(h[7:], JWT_SECRET, algorithms=["HS256"])
    except Exception:
        raise ApiError(401, "Session expired. Please login again.")
    g.email = c.get("sub")
    g.role = c.get("role")
    if path.startswith("/api/admin/") and g.role != "admin":
        raise ApiError(403, "Admin only")
    return None


# ------------------------------------------------------------------------- pages
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/healthz")
def healthz():
    return "ok"


# -------------------------------------------------------------------- user auth
def user_dto(u):
    return {"name": u["name"], "email": u["email"], "phone": u["phone"], "city": u["city"] or ""}


def log_event(u, kind):
    query("INSERT INTO vd_login_log (email,name,phone,kind,at_time) VALUES (?,?,?,?,?)",
          (u["email"], u["name"], u["phone"], kind, now_ms()), commit=True)


@app.post("/api/auth/register")
def register():
    b = body()
    name, email = clean(b.get("name")), clean(b.get("email")).lower()
    phone, pw = clean(b.get("phone")), clean(b.get("password"))
    if not EMAIL_RE.match(email):
        raise ApiError(400, "Enter a valid email.")
    if len(pw) < 6:
        raise ApiError(400, "Password must be at least 6 characters.")
    if not name:
        raise ApiError(400, "Enter your name.")
    if not valid_phone(phone):
        raise ApiError(400, "Enter a valid mobile number (10 digits).")
    if query("SELECT id FROM vd_users WHERE email=?", (email,), one=True):
        raise ApiError(409, "This email is already registered. Please login.")
    try:
        query("INSERT INTO vd_users (name,email,password_hash,phone,city,created_at) VALUES (?,?,?,?,?,?)",
              (name, email, generate_password_hash(pw), phone, "", now_ms()), commit=True)
    except Exception:
        raise ApiError(409, "This email is already registered. Please login.")
    u = query("SELECT * FROM vd_users WHERE email=?", (email,), one=True)
    log_event(u, "register")
    return jsonify(token=make_token(email, "user"), user=user_dto(u))


@app.post("/api/auth/login")
def login():
    b = body()
    email, pw = clean(b.get("email")).lower(), clean(b.get("password"))
    key = "u:" + email
    rl_check(key)
    u = query("SELECT * FROM vd_users WHERE email=?", (email,), one=True)
    if not u or not check_password_hash(u["password_hash"], pw):
        rl_fail(key)
        raise ApiError(401, "Wrong email or password.")
    rl_ok(key)
    log_event(u, "login")
    return jsonify(token=make_token(email, "user"), user=user_dto(u))


@app.get("/api/auth/me")
def me():
    if g.role != "user":
        raise ApiError(403, "Not a user session")
    u = query("SELECT * FROM vd_users WHERE email=?", (g.email,), one=True)
    if not u:
        raise ApiError(401, "Account not found")
    return jsonify(user_dto(u))


# ---------------------------------------------------------------------- listings
def listing_dto(r):
    return {
        "id": r["id"], "t": r["title"], "p": r["price"], "o": r["orig_price"], "c": r["category"],
        "type": r["prod_type"], "cond": r["cond_text"], "age": r["age_text"], "q": r["quality"],
        "desc": r["descr"], "img": r["img"], "hash": r["img_hash"], "owner": r["owner_email"],
        "sName": r["seller_name"], "sPhone": r["seller_phone"], "sCity": r["seller_city"],
        "at": r["created_at"],
    }


def norm(s):
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def hamming(a, b):
    if len(a) != len(b):
        return 10 ** 9
    return sum(x != y for x, y in zip(a, b))


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


@app.get("/api/listings")
def listings_all():
    rows = query("SELECT * FROM vd_listings ORDER BY created_at DESC")
    return jsonify([listing_dto(r) for r in rows])


@app.post("/api/listings")
def listings_create():
    if g.role != "user":
        raise ApiError(403, "Only users can upload products")
    email = g.email
    u = query("SELECT * FROM vd_users WHERE email=?", (email,), one=True)
    if not u:
        raise ApiError(401, "Account not found")
    b = body()

    title = clean(b.get("t"))
    price = to_int(b.get("p"))
    orig = to_int(b.get("o"))
    s_name, s_phone, s_city = clean(b.get("sName")), clean(b.get("sPhone")), clean(b.get("sCity"))
    img = b.get("img") if isinstance(b.get("img"), str) else None
    h = b.get("hash") if isinstance(b.get("hash"), str) else None

    if not title:
        raise ApiError(400, "Please enter a title")
    if price is None or price <= 0:
        raise ApiError(400, "Enter a valid price")
    if not clean(b.get("type")):
        raise ApiError(400, "Please mention the product type")
    if not s_name:
        raise ApiError(400, "Enter your name")
    if not valid_phone(s_phone):
        raise ApiError(400, "Enter a valid mobile number")
    if not s_city:
        raise ApiError(400, "Enter your city or area")
    if img and len(img) > 8_000_000:
        raise ApiError(413, "Image is too large")

    nt = norm(title)
    for r in query("SELECT title FROM vd_listings WHERE owner_email=?", (email,)):
        if norm(r["title"]) == nt:
            raise ApiError(409, "Duplicate: a listing with this title already exists")
    if h:
        for r in query("SELECT img_hash FROM vd_listings WHERE img_hash IS NOT NULL AND img_hash <> ''"):
            if hamming(r["img_hash"], h) <= 3:
                raise ApiError(409, "Duplicate: this photo was already uploaded")

    lid = "u" + str(now_ms()) + uuid.uuid4().hex[:6]
    if orig is None or orig < price:
        orig = price
    query("""INSERT INTO vd_listings
        (id,title,price,orig_price,category,prod_type,cond_text,age_text,quality,descr,img,img_hash,
         owner_email,seller_name,seller_phone,seller_city,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (lid, title, price, orig, clean(b.get("c")), clean(b.get("type")), clean(b.get("cond")),
           clean(b.get("age")), to_int(b.get("q")), (b.get("desc") or "")[:2000], img, h,
           email, s_name, s_phone, s_city, now_ms()), commit=True)
    query("UPDATE vd_users SET name=?, phone=?, city=? WHERE email=?",
          (s_name, s_phone, s_city, email), commit=True)
    row = query("SELECT * FROM vd_listings WHERE id=?", (lid,), one=True)
    return jsonify(listing_dto(row))


@app.delete("/api/listings/<lid>")
def listings_delete(lid):
    r = query("SELECT owner_email FROM vd_listings WHERE id=?", (lid,), one=True)
    if not r:
        raise ApiError(404, "Listing not found")
    if g.role != "admin" and r["owner_email"] != g.email:
        raise ApiError(403, "You can delete only your own listings")
    query("DELETE FROM vd_listings WHERE id=?", (lid,), commit=True)
    return jsonify(deleted=True)


# ------------------------------------------------------------------------- admin
@app.get("/api/admin/status")
def admin_status():
    r = query("SELECT COUNT(*) AS n FROM vd_admin", one=True)
    return jsonify(configured=r["n"] > 0)


@app.post("/api/admin/setup")
def admin_setup():
    b = body()
    email, pw = clean(b.get("email")).lower(), clean(b.get("password"))
    if query("SELECT COUNT(*) AS n FROM vd_admin", one=True)["n"] > 0:
        raise ApiError(403, "Admin already exists.")
    if not EMAIL_RE.match(email):
        raise ApiError(400, "Enter a valid email.")
    if len(pw) < 8:
        raise ApiError(400, "Password must be at least 8 characters.")
    try:  # id is always 1 -> a second admin row is impossible
        query("INSERT INTO vd_admin (id,email,password_hash) VALUES (1,?,?)",
              (email, generate_password_hash(pw)), commit=True)
    except Exception:
        raise ApiError(403, "Admin already exists.")
    return jsonify(token=make_token(email, "admin"))


@app.post("/api/admin/login")
def admin_login():
    b = body()
    key = "a:" + (request.remote_addr or "?")
    rl_check(key)
    email, pw = clean(b.get("email")).lower(), clean(b.get("password"))
    a = query("SELECT * FROM vd_admin WHERE id=1", one=True)
    if not a:
        raise ApiError(404, "Admin is not set up yet.")
    if a["email"] != email or not check_password_hash(a["password_hash"], pw):
        rl_fail(key)
        raise ApiError(401, "Wrong admin email or password.")
    rl_ok(key)
    return jsonify(token=make_token(email, "admin"))


@app.get("/api/admin/users")
def admin_users():
    out = []
    for u in query("SELECT * FROM vd_users ORDER BY created_at DESC"):
        n = query("SELECT COUNT(*) AS n FROM vd_listings WHERE owner_email=?", (u["email"],), one=True)["n"]
        last = query("SELECT at_time FROM vd_login_log WHERE email=? ORDER BY at_time DESC LIMIT 1",
                     (u["email"],), one=True)
        out.append({"name": u["name"], "email": u["email"], "phone": u["phone"], "city": u["city"],
                    "createdAt": u["created_at"], "uploads": n,
                    "lastLogin": last["at_time"] if last else None})
    return jsonify(out)


@app.get("/api/admin/logins")
def admin_logins():
    rows = query("SELECT * FROM vd_login_log ORDER BY at_time DESC LIMIT 500")
    return jsonify([{"id": r["id"], "email": r["email"], "name": r["name"], "phone": r["phone"],
                     "type": r["kind"], "at": r["at_time"]} for r in rows])


@app.get("/api/admin/listings")
def admin_listings():
    rows = query("SELECT * FROM vd_listings ORDER BY created_at DESC")
    return jsonify([listing_dto(r) for r in rows])


@app.delete("/api/admin/listings/<lid>")
def admin_delete(lid):
    if not query("SELECT id FROM vd_listings WHERE id=?", (lid,), one=True):
        raise ApiError(404, "Listing not found")
    query("DELETE FROM vd_listings WHERE id=?", (lid,), commit=True)
    return jsonify(deleted=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
