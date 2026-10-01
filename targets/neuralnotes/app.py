"""NeuralNotes — a deliberately vulnerable "AI notes" app (Flask + SQLite).

PART OF A SECURITY TEST LAB. Every weakness below is INTENTIONAL and documented
in ../INTENDED-VULNS.md. Do not deploy anywhere real.

Stack: Python / Flask / SQLite.
"""
import sqlite3
import urllib.request

from flask import Flask, make_response, request

app = Flask(__name__)
DB = "/tmp/neuralnotes.db"


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT, password TEXT, name TEXT);
    CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT, private INTEGER);
    """)
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        c.executescript("""
        INSERT INTO users(email,password,name) VALUES
          ('admin@neuralnotes.ai','S3cretAdmin!','Admin'),
          ('alice@neuralnotes.ai','alicepw','Alice');
        INSERT INTO notes(user_id,title,body,private) VALUES
          (1,'Admin API keys','OPENAI_KEY=sk-ADMIN-SECRET-7f3a',1),
          (2,'Grocery list','milk, eggs, coffee',0),
          (2,'Model ideas','fine-tune on support tickets',0),
          (1,'Alice SSN note','SSN 111-22-3333',1);
        """)
    c.commit()
    c.close()


PAGE = """<!doctype html><html><head><title>NeuralNotes</title></head><body>
<h1>🧠 NeuralNotes</h1>
<nav><a href="/">home</a> | <a href="/login">login</a> | <a href="/search">search</a>
 | <a href="/summarize">summarize</a></nav><hr>{body}</body></html>"""


@app.route("/")
def home():
    return PAGE.format(body=(
        '<p>AI-powered personal notes.</p>'
        '<form action="/search"><input name="q" placeholder="search notes">'
        '<button>Search</button></form>'))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "")
        pw = request.form.get("password", "")
        # VULN #1 — SQL injection (auth bypass). User input concatenated into SQL.
        sql = "SELECT * FROM users WHERE email='%s' AND password='%s'" % (email, pw)
        c = db()
        try:
            row = c.execute(sql).fetchone()
        except Exception as e:  # noqa: BLE001
            return PAGE.format(body=f"<p>DB error: {e}</p>")
        finally:
            c.close()
        if row:
            resp = make_response(PAGE.format(body=f"<p>Welcome back, {row['name']}!</p>"))
            resp.set_cookie("uid", str(row["id"]))
            return resp
        return PAGE.format(body="<p>Invalid credentials.</p>")
    return PAGE.format(body=(
        '<form method="post"><input name="email" placeholder="email">'
        '<input name="password" type="password" placeholder="password">'
        '<button>Login</button></form>'))


@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows, err = [], ""
    if q:
        c = db()
        try:
            # VULN #2 — SQL injection in the search query (string-formatted LIKE).
            rows = c.execute(
                "SELECT title, body FROM notes WHERE private=0 AND title LIKE '%%%s%%'" % q
            ).fetchall()
        except Exception as e:  # noqa: BLE001
            err = str(e)
        finally:
            c.close()
    items = "".join(f"<li><b>{r['title']}</b>: {r['body']}</li>" for r in rows)
    # VULN #3 — reflected XSS: q echoed into the page without escaping.
    return PAGE.format(body=(
        f'<form action="/search"><input name="q" value="{q}"><button>Search</button></form>'
        f"<p>Results for: {q}</p><ul>{items}</ul>"
        + (f"<p>error: {err}</p>" if err else "")))


@app.route("/api/note/<int:nid>")
def note(nid):
    # VULN #4 — IDOR: returns ANY note (including private ones) with no auth or
    # ownership check. /api/note/1 and /api/note/4 leak private notes.
    c = db()
    r = c.execute("SELECT id,user_id,title,body,private FROM notes WHERE id=?", (nid,)).fetchone()
    c.close()
    if not r:
        return {"error": "not found"}, 404
    return dict(r)


@app.route("/summarize")
def summarize():
    url = request.args.get("url", "")
    if not url:
        return PAGE.format(body=(
            '<p>Summarize any webpage with AI:</p>'
            '<form action="/summarize"><input name="url" placeholder="https://...">'
            '<button>Summarize</button></form>'))
    # VULN #5 — SSRF: fetches an arbitrary URL server-side (incl. internal hosts
    # and cloud metadata), returning the body.
    try:
        data = urllib.request.urlopen(url, timeout=5).read(2000).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        data = f"error: {e}"
    return PAGE.format(body=f"<p>Summary of {url}:</p><pre>{data}</pre>")


init()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
