"""Team ERP: sign in/out attendance, BOD/EOD reports, role admin, Excel/Sheets export."""
import io
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo

from flask import (Flask, abort, flash, g, redirect, render_template_string,
                   request, send_file, session, url_for)
from jinja2 import DictLoader
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("ERP_DB", os.path.join(BASE, "erp.db"))
try:
    TZ = ZoneInfo(os.environ.get("ERP_TZ", "Asia/Kolkata"))
except Exception:  # Windows has no tz database unless `tzdata` is installed
    TZ = timezone(timedelta(hours=5, minutes=30), "IST")
ROLES = ["Member", "RND", "MO", "CO", "CA", "Admin"]

# (username, display name, role, can_view_all, can_download_all)
SEED = [
    ("Sibi", "Sibi (Admin)", "Admin", 1, 1),
    ("Tharun", "Tharun", "RND", 0, 1),
    ("Darshan", "Darshan", "RND", 0, 0),
    ("Prasana", "Prasana", "MO", 0, 1),
    ("Rishi", "Rishi", "MO", 0, 0),
    ("Harish", "Harish", "Member", 0, 0),
    ("Jai", "Jai", "Member", 0, 0),
]

app = Flask(__name__)


def _secret():
    if os.environ.get("ERP_SECRET"):
        return os.environ["ERP_SECRET"]
    p = os.path.join(BASE, ".secret_key")
    if not os.path.exists(p):
        with open(p, "w") as f:
            f.write(secrets.token_hex(32))
    return open(p).read().strip()


app.secret_key = _secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=12))


# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  pw_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'Member',
  can_view_all INTEGER NOT NULL DEFAULT 0, can_download INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, day TEXT NOT NULL,
  sign_in TEXT NOT NULL, sign_out TEXT, in_note TEXT DEFAULT '', out_note TEXT DEFAULT '',
  bod TEXT NOT NULL DEFAULT '', eod TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_sessions_day ON sessions(day);
"""

KEEP_DAYS = 7  # data kept: today + the previous 7 days; older rows are deleted automatically


def window_start():
    return (now() - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%d")


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    # one-time migration from the old one-row-per-day tables
    if con.execute("SELECT 1 FROM sqlite_master WHERE name='attendance'").fetchone():
        con.execute("""INSERT INTO sessions(user_id,day,sign_in,sign_out,in_note,out_note,bod,eod)
            SELECT a.user_id,a.day,a.sign_in,a.sign_out,a.in_note,a.out_note,
                   COALESCE(r.bod,''),COALESCE(r.eod,'') FROM attendance a
            LEFT JOIN reports r ON r.user_id=a.user_id AND r.day=a.day WHERE a.sign_in IS NOT NULL""")
        con.execute("DROP TABLE attendance")
        con.execute("DROP TABLE IF EXISTS reports")
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        lines = ["ERP login credentials (change after first login, then delete this file)", ""]
        for u, n, r, v, d in SEED:
            pw = secrets.token_urlsafe(8)
            con.execute("INSERT INTO users(username,name,pw_hash,role,can_view_all,can_download)"
                        " VALUES(?,?,?,?,?,?)", (u, n, generate_password_hash(pw), r, v, d))
            lines.append(f"{u:<10} {pw}   ({r})")
        with open(os.path.join(BASE, "CREDENTIALS.txt"), "w") as f:
            f.write("\n".join(lines) + "\n")
    con.execute("UPDATE users SET role='Member' WHERE role='Export'")
    con.execute("DELETE FROM sessions WHERE day < ?", (window_start(),))
    con.commit()
    con.close()


_last_purge = [None]


def purge_old():
    t = today()
    if _last_purge[0] != t:
        db().execute("DELETE FROM sessions WHERE day < ?", (window_start(),))
        db().commit()
        _last_purge[0] = t


# ---------- helpers ----------
def now():
    return datetime.now(TZ)


def today():
    return now().strftime("%Y-%m-%d")


def stamp():
    return now().strftime("%Y-%m-%d %H:%M:%S")


def hhmm(s):
    return s[11:16] if s else ""


def secs(a, b):
    f = "%Y-%m-%d %H:%M:%S"
    return max((datetime.strptime(b, f) - datetime.strptime(a, f)).total_seconds(), 0)


def hours(a, b):
    return round(secs(a, b) / 3600, 2) if (a and b) else ""


def me():
    if "uid" not in session:
        return None
    if not hasattr(g, "me"):
        g.me = db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    return g.me


def is_admin(u=None):
    u = u or me()
    return bool(u and u["role"] == "Admin")


def can_see_sheet(u=None):
    """Every logged-in member can see the team's attendance (no BOD/EOD)."""
    return bool(u or me())


def can_download(u=None):
    """Only Admin (any day in the window) and members granted it (today only): Tharun, Prasana."""
    u = u or me()
    return bool(u and (u["role"] == "Admin" or u["can_download"]))


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not me():
            return redirect(url_for("login"))
        return f(*a, **k)
    return w


def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if not is_admin():
            abort(403)
        return f(*a, **k)
    return w


@app.before_request
def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST" and request.form.get("csrf") != session["csrf"]:
        abort(400, "Bad CSRF token")
    purge_old()


@app.context_processor
def ctx():
    return dict(me=me(), is_admin=is_admin, can_see_sheet=can_see_sheet,
                can_download=can_download, today=today, window_start=window_start, hhmm=hhmm, csrf_token=session.get("csrf", ""),
                ROLES=ROLES)


def get_rows(start, end, absent_day=None):
    """One row per sign-in session. With absent_day, members with no session that day get an Absent row."""
    d = db()
    users = {u["id"]: u for u in d.execute("SELECT * FROM users")}
    sess = d.execute("SELECT * FROM sessions WHERE day BETWEEN ? AND ? ORDER BY sign_in", (start, end)).fetchall()
    totals = {}
    for s in sess:
        if s["sign_out"]:
            k = (s["user_id"], s["day"])
            totals[k] = totals.get(k, 0) + secs(s["sign_in"], s["sign_out"])
    rows, seen = [], set()
    for s in sess:
        u, k = users[s["user_id"]], (s["user_id"], s["day"])
        seen.add(k)
        rows.append(dict(
            name=u["name"], username=u["username"], role=u["role"], day=s["day"],
            status="Signed out" if s["sign_out"] else "Signed in",
            sign_in=hhmm(s["sign_in"]), sign_out=hhmm(s["sign_out"]), hours=hours(s["sign_in"], s["sign_out"]),
            day_total=round(totals.get(k, 0) / 3600, 2), in_note=s["in_note"], out_note=s["out_note"],
            bod=s["bod"], eod=s["eod"]))
    if absent_day:
        for uid, u in users.items():
            if (uid, absent_day) not in seen:
                rows.append(dict(name=u["name"], username=u["username"], role=u["role"], day=absent_day,
                                 status="Absent", sign_in="", sign_out="", hours="", day_total=0,
                                 in_note="", out_note="", bod="", eod=""))
    rows.sort(key=lambda r: (r["day"], r["name"].lower(), r["sign_in"]))
    return rows


COLS = [("Name", "name"), ("Sign in", "sign_in"), ("Sign out", "sign_out"),
        ("BOD (plan)", "bod"), ("EOD (summary)", "eod")]


# On-screen team view: attendance and hours only. BOD/EOD and notes are in the download.
VIEW_COLS = [("Name", "name"), ("Sign in", "sign_in"), ("Sign out", "sign_out")]


def xlsx_response(rows, filename, title):
    wb = Workbook()
    ws = wb.active
    ws.title = title[:31]
    ws.append([c[0] for c in COLS])
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F3A5F")
    for r in rows:
        ws.append([r[k] for _, k in COLS])
    widths = [18, 10, 10, 55, 55]
    for i, w in enumerate(widths):
        ws.column_dimensions[chr(65 + i)].width = w
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "A2"
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=filename,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


def valid_day(s):
    """A YYYY-MM-DD inside the retained window, else today."""
    try:
        datetime.strptime(s, "%Y-%m-%d")
    except (TypeError, ValueError):
        return today()
    return s if window_start() <= s <= today() else today()


# ---------- auth ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE lower(username)=lower(?)",
                         (request.form.get("username", "").strip(),)).fetchone()
        if u and check_password_hash(u["pw_hash"], request.form.get("password", "")):
            session.clear()
            session.permanent = True
            session["uid"] = u["id"]
            session["csrf"] = secrets.token_hex(16)
            return redirect(url_for("home"))
        flash("Wrong username or password.", "err")
    return render_template_string(T["login"])


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- member pages ----------
@app.route("/")
@login_required
def home():
    d, u, t = db(), me(), today()
    open_s = d.execute("SELECT * FROM sessions WHERE user_id=? AND sign_out IS NULL", (u["id"],)).fetchone()
    hist = [r for r in get_rows(window_start(), t) if r["username"] == u["username"]][::-1]
    total = next((r["day_total"] for r in hist if r["day"] == t), 0)
    return render_template_string(T["home"], open_s=open_s, hist=hist, total=total,
                                  clock=now().strftime("%A, %d %b %Y"))


@app.post("/signin")
@login_required
def signin():
    u, d = me(), db()
    bod = request.form.get("bod", "").strip()[:5000]
    if not bod:
        flash("Fill your BOD (plan for the day) to sign in.", "err")
    elif d.execute("SELECT 1 FROM sessions WHERE user_id=? AND sign_out IS NULL", (u["id"],)).fetchone():
        flash("You are already signed in.", "err")
    else:
        d.execute("INSERT INTO sessions(user_id,day,sign_in,in_note,bod) VALUES(?,?,?,?,?)",
                  (u["id"], today(), stamp(), request.form.get("note", "").strip()[:200], bod))
        d.commit()
        flash("Signed in. BOD saved.", "ok")
    return redirect(url_for("home"))


@app.post("/signout")
@login_required
def signout():
    u, d = me(), db()
    eod = request.form.get("eod", "").strip()[:5000]
    row = d.execute("SELECT * FROM sessions WHERE user_id=? AND sign_out IS NULL", (u["id"],)).fetchone()
    if not row:
        flash("You are not signed in.", "err")
    elif not eod:
        flash("Fill your EOD (what you did) to sign out.", "err")
    else:
        d.execute("UPDATE sessions SET sign_out=?, out_note=?, eod=? WHERE id=?",
                  (stamp(), request.form.get("note", "").strip()[:200], eod, row["id"]))
        d.commit()
        flash("Signed out. EOD saved.", "ok")
    return redirect(url_for("home"))


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    if request.method == "POST":
        u = me()
        new = request.form.get("new", "")
        if not check_password_hash(u["pw_hash"], request.form.get("old", "")):
            flash("Current password is wrong.", "err")
        elif len(new) < 6:
            flash("New password must be at least 6 characters.", "err")
        else:
            db().execute("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(new), u["id"]))
            db().commit()
            flash("Password changed.", "ok")
            return redirect(url_for("home"))
    return render_template_string(T["password"])


# ---------- team sheet ----------
@app.route("/sheet")
@login_required
def sheet():
    if not can_see_sheet():
        abort(403)
    day = valid_day(request.args.get("date"))
    rows = get_rows(day, day, day)
    return render_template_string(T["sheet"], rows=rows, day=day, cols=VIEW_COLS)


@app.route("/download")
@login_required
def download():
    """Admin: any day in the retained window. granted members (Tharun, Prasana): today only."""
    if not can_download():
        abort(403)
    day = valid_day(request.args.get("date")) if is_admin() else today()
    return xlsx_response(get_rows(day, day, day), f"ERP_{day}.xlsx", day)


# ---------- admin ----------
@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    d = db()
    if request.method == "POST":
        uid = int(request.form["uid"])
        target = d.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not target:
            abort(404)
        act = request.form.get("act")
        if act == "save":
            role = request.form.get("role")
            if role not in ROLES:
                abort(400)
            admins = d.execute("SELECT COUNT(*) FROM users WHERE role='Admin'").fetchone()[0]
            if target["role"] == "Admin" and role != "Admin" and admins <= 1:
                flash("There must be at least one Admin.", "err")
            else:
                d.execute("UPDATE users SET role=?, can_download=? WHERE id=?",
                          (role, int(bool(request.form.get("dl"))), uid))
                d.commit()
                flash(f"Updated {target['name']}.", "ok")
        elif act == "reset":
            pw = request.form.get("pw", "")
            if len(pw) < 6:
                flash("Password must be at least 6 characters.", "err")
            else:
                d.execute("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(pw), uid))
                d.commit()
                flash(f"Password reset for {target['name']}.", "ok")
        return redirect(url_for("admin"))
    users = d.execute("SELECT * FROM users ORDER BY id").fetchall()
    return render_template_string(T["admin"], users=users)


@app.errorhandler(403)
def forbidden(_):
    return render_template_string(T["msg"], title="No access", text="You don't have permission to view this page."), 403


# ---------- templates ----------
CSS = """
:root{--bg:#f4f6fa;--card:#fff;--ink:#17202e;--mute:#667085;--line:#e3e8ef;--brand:#1f3a5f;--acc:#2f6fed;--ok:#157f4b;--err:#b42318}
@media(prefers-color-scheme:dark){:root{--bg:#0f141c;--card:#171e29;--ink:#e8edf5;--mute:#93a0b4;--line:#263041;--brand:#0b1220;--acc:#5b8cff;--ok:#4ade80;--err:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
nav{background:var(--brand);color:#fff;display:flex;gap:6px;align-items:center;padding:10px 20px;flex-wrap:wrap}
nav b{margin-right:14px;font-size:17px}nav a,nav button{color:#dbe6f7;text-decoration:none;padding:6px 12px;border-radius:8px;background:none;border:0;font:inherit;cursor:pointer}
nav a:hover,nav button:hover{background:rgba(255,255,255,.14)}nav .sp{flex:1}nav form{margin:0}
main{max-width:1180px;margin:22px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:18px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:0 0 12px}.mute{color:var(--mute)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:18px}
input,select,textarea{width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font:inherit}
textarea{min-height:130px;resize:vertical}label{font-size:13px;color:var(--mute);display:block;margin:10px 0 4px}
.btn{display:inline-block;background:var(--acc);color:#fff;border:0;padding:9px 18px;border-radius:9px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none}
.btn.out{background:#c2410c}.btn.ghost{background:transparent;color:var(--acc);border:1px solid var(--acc)}.btn[disabled]{opacity:.45;cursor:not-allowed}
.flash{padding:10px 14px;border-radius:10px;margin-bottom:14px;border:1px solid}.flash.ok{color:var(--ok);border-color:var(--ok)}.flash.err{color:var(--err);border-color:var(--err)}
.tbl{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:var(--bg);font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mute);position:sticky;top:0;white-space:nowrap}
td.wrap{min-width:240px;white-space:pre-wrap}.pill{padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;background:var(--bg);border:1px solid var(--line)}
.pill.p{color:var(--ok)}.pill.a{color:var(--err)}.row{display:flex;gap:10px;align-items:end;flex-wrap:wrap}.row>div{flex:0 0 auto}
.big{font-size:30px;font-weight:700}.login{max-width:380px;margin:12vh auto}
"""

LAYOUT = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Team ERP</title><style>""" + CSS + """</style></head><body>
{% if me %}<nav><b>Team ERP</b><a href="{{ url_for('home') }}">My day</a>
{% if can_see_sheet() %}<a href="{{ url_for('sheet') }}">Team sheet</a>{% endif %}
{% if can_download() %}<a href="{{ url_for('download') }}">Download today</a>{% endif %}
{% if is_admin() %}<a href="{{ url_for('admin') }}">Roles &amp; access</a>{% endif %}
<span class="sp"></span><span>{{ me['name'] }} · {{ me['role'] }}</span><a href="{{ url_for('password') }}">Password</a>
<form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf_token }}"><button>Log out</button></form></nav>{% endif %}
<main>{% for c, m in get_flashed_messages(with_categories=true) %}<div class="flash {{ c }}">{{ m }}</div>{% endfor %}
{% block body %}{% endblock %}</main></body></html>"""

T = {}
T["login"] = """{% extends 'layout' %}{% block body %}<div class="login card"><h1>Team ERP</h1><p class="mute">Sign in to mark your attendance and submit BOD / EOD.</p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token }}">
<label>Username</label><input name="username" autofocus required autocomplete="username">
<label>Password</label><input name="password" type="password" required autocomplete="current-password">
<p><button class="btn" style="width:100%">Log in</button></p></form></div>{% endblock %}"""

T["msg"] = """{% extends 'layout' %}{% block body %}<div class="card"><h1>{{ title }}</h1><p class="mute">{{ text }}</p></div>{% endblock %}"""

T["password"] = """{% extends 'layout' %}{% block body %}<div class="card" style="max-width:420px"><h1>Change password</h1>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token }}">
<label>Current password</label><input type="password" name="old" required>
<label>New password (min 6)</label><input type="password" name="new" required>
<p><button class="btn">Save</button></p></form></div>{% endblock %}"""

T["home"] = """{% extends 'layout' %}{% block body %}
<div class="card"><h1>Hello, {{ me['name'] }}</h1><div class="mute">{{ clock }}</div>
<div class="row" style="margin:14px 0;align-items:center;gap:36px">
 <div><div class="mute">Status</div><div class="big">{% if open_s %}Signed in <span class="mute" style="font-size:16px">since {{ hhmm(open_s['sign_in']) }}</span>{% else %}Signed out{% endif %}</div></div>
 </div>
{% if open_s %}
<div class="mute">BOD for this session: <i>{{ open_s['bod'] }}</i></div>
<form method="post" action="{{ url_for('signout') }}"><input type="hidden" name="csrf" value="{{ csrf_token }}">
 <label>EOD — what did you finish? Blockers? (required to sign out)</label>
 <textarea name="eod" required placeholder="Summary of this session"></textarea>
 <label>Note (optional)</label><input name="note" maxlength="200">
 <p><button class="btn out">Sign out</button></p></form>
{% else %}
<form method="post" action="{{ url_for('signin') }}"><input type="hidden" name="csrf" value="{{ csrf_token }}">
 <label>BOD — what will you work on? (required to sign in)</label>
 <textarea name="bod" required placeholder="Plan for this session"></textarea>
 <label>Note (optional) e.g. WFH, on-site</label><input name="note" maxlength="200">
 <p><button class="btn">Sign in</button></p></form>
{% endif %}</div>
<div class="card"><h2>My sessions (last 7 days)</h2><div class="tbl"><table><tr><th>Date</th><th>In</th><th>Out</th><th>BOD</th><th>EOD</th></tr>
{% for r in hist %}<tr><td>{{ r.day }}</td><td>{{ r.sign_in }}</td><td>{{ r.sign_out or 'in progress' }}</td><td class="wrap">{{ r.bod }}</td><td class="wrap">{{ r.eod }}</td></tr>
{% else %}<tr><td colspan="5" class="mute">Nothing yet.</td></tr>{% endfor %}</table></div>
<p class="mute">Records older than 7 days are deleted automatically.</p></div>{% endblock %}"""

T["sheet"] = """{% extends 'layout' %}{% block body %}
<div class="card"><div class="row"><div><h1>Team sheet</h1><div class="mute">Everyone's sign-in and sign-out times.</div></div>
<span style="flex:1"></span>
<form method="get" class="row"><div><label>Date</label><input type="date" name="date" value="{{ day }}" min="{{ window_start() }}" max="{{ today() }}"></div><div><button class="btn ghost">View</button></div></form>
{% if can_download() and (is_admin() or day == today()) %}<div><a class="btn" href="{{ url_for('download', date=day) }}">Download this day (.xlsx)</a></div>{% endif %}</div></div>
<div class="card tbl"><table><tr>{% for h, k in cols %}{% if k != 'day' %}<th>{{ h }}</th>{% endif %}{% endfor %}</tr>
{% for r in rows %}<tr>{% for h, k in cols %}{% if k != 'day' %}<td class="{{ 'wrap' if k in ('bod','eod') else '' }}">
{% if k == 'status' %}<span class="pill {{ 'a' if r.status == 'Absent' else 'p' }}">{{ r.status }}</span>{% else %}{{ r[k] }}{% endif %}</td>{% endif %}{% endfor %}</tr>
{% else %}<tr><td colspan="3" class="mute">No data.</td></tr>{% endfor %}</table></div>{% endblock %}"""

T["admin"] = """{% extends 'layout' %}{% block body %}
<div class="card"><h1>Roles &amp; access</h1><p class="mute">Only Admin can change roles (labels: RND, MO, CO, CA). Everyone can view the team's sign-in / sign-out times and hours, but only Admin and members ticked “Download today” can download the sheet that includes BOD and EOD: Admin any day of the last 7 days, the others today only. Records older than 7 days are deleted automatically.</p>
<div class="tbl"><table><tr><th>Name</th><th>Username</th><th>Role</th><th>Download today</th><th></th><th>Reset password</th></tr>
{% for u in users %}<tr><form method="post" id="f{{u.id}}"><input type="hidden" name="csrf" value="{{ csrf_token }}"><input type="hidden" name="uid" value="{{u.id}}"><input type="hidden" name="act" value="save"></form>
<td>{{ u.name }}</td><td>{{ u.username }}</td>
<td><select name="role" form="f{{u.id}}">{% for r in ROLES %}<option {{ 'selected' if r == u.role }}>{{ r }}</option>{% endfor %}</select></td>
<td><input type="checkbox" name="dl" form="f{{u.id}}" {{ 'checked' if u.can_download }} style="width:auto"></td>
<td><button class="btn" form="f{{u.id}}">Save</button></td>
<td><form method="post" class="row"><input type="hidden" name="csrf" value="{{ csrf_token }}"><input type="hidden" name="uid" value="{{u.id}}"><input type="hidden" name="act" value="reset">
<input name="pw" placeholder="new password" style="width:150px"><button class="btn ghost">Reset</button></form></td></tr>{% endfor %}</table></div></div>{% endblock %}"""

app.jinja_loader = DictLoader({"layout": LAYOUT})

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
