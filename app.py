from flask import Flask, request, jsonify, send_from_directory, render_template
import sqlite3, os, hashlib, time
from flask_cors import CORS

DB = "pvt_chat.db"
ADMIN_DEFAULT_KEY = "vxnihba"

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY,
                admin_key TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY,
                key_text TEXT UNIQUE,
                created_at INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY,
                device_id TEXT,
                key_text TEXT,
                name TEXT,
                last_seen INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                key_text TEXT,
                device_id TEXT,
                name TEXT,
                type TEXT,
                content TEXT,
                ts INTEGER
    )""")
    conn.commit()
    # ensure admin row exists
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as cnt FROM admin")
    if cur.fetchone()["cnt"] == 0:
        cur.execute("INSERT INTO admin (admin_key) VALUES (?)", (ADMIN_DEFAULT_KEY,))
        conn.commit()
    conn.close()

init_db()

# --- Admin endpoints ---
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.json or {}
    key = data.get("admin_key","").strip()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT admin_key FROM admin LIMIT 1")
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": False, "error": "server admin missing"}), 500
    if key == row["admin_key"]:
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "invalid key"}), 401

@app.route("/api/admin/get_keys", methods=["GET"])
def admin_get_keys():
    # simple auth by admin_key in header
    admin_key = request.headers.get("X-Admin-Key","")
    conn = get_db()
    row = conn.execute("SELECT admin_key FROM admin LIMIT 1").fetchone()
    if not row or admin_key != row["admin_key"]:
        conn.close()
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    cur = conn.cursor()
    ks = [dict(r) for r in cur.execute("SELECT key_text, created_at FROM keys ORDER BY created_at DESC").fetchall()]
    # attach active devices per key
    out = []
    for k in ks:
        devices = [dict(d) for d in cur.execute("SELECT device_id,name,last_seen FROM devices WHERE key_text=?",(k["key_text"],)).fetchall()]
        out.append({"key": k["key_text"], "created_at": k["created_at"], "devices": devices})
    conn.close()
    return jsonify({"ok": True, "keys": out})

@app.route("/api/admin/create_key", methods=["POST"])
def admin_create_key():
    data = request.json or {}
    admin_key = request.headers.get("X-Admin-Key","")
    conn = get_db()
    row = conn.execute("SELECT admin_key FROM admin LIMIT 1").fetchone()
    if not row or admin_key != row["admin_key"]:
        conn.close()
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    key_text = (data.get("key") or "").strip()
    if not key_text:
        conn.close()
        return jsonify({"ok": False, "error": "empty key"}), 400
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO keys (key_text, created_at) VALUES (?,?)", (key_text, int(time.time())))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "key": key_text})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"ok": False, "error": "key exists"}), 400

@app.route("/api/admin/change_key", methods=["POST"])
def admin_change_key():
    # change admin key (current required)
    data = request.json or {}
    admin_key = request.headers.get("X-Admin-Key","")
    conn = get_db()
    cur = conn.cursor()
    row = cur.execute("SELECT admin_key FROM admin LIMIT 1").fetchone()
    if not row or admin_key != row["admin_key"]:
        conn.close()
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    new_key = (data.get("new_key") or "").strip()
    if not new_key:
        conn.close()
        return jsonify({"ok": False, "error": "empty new key"}), 400
    cur.execute("UPDATE admin SET admin_key=? WHERE id=1", (new_key,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

# --- User/device endpoints ---
@app.route("/api/join", methods=["POST"])
def join_room():
    data = request.json or {}
    name = (data.get("name") or "").strip()
    key = (data.get("key") or "").strip()
    device = (data.get("device_id") or "").strip()
    if not name or not key or not device:
        return jsonify({"ok": False, "error": "missing params"}), 400
    conn = get_db(); cur = conn.cursor()
    # does key exist?
    k = cur.execute("SELECT key_text FROM keys WHERE key_text=?",(key,)).fetchone()
    if not k:
        conn.close()
        return jsonify({"ok": False, "error": "invalid key"}), 404
    # gather devices for key
    devs = [d["device_id"] for d in cur.execute("SELECT device_id FROM devices WHERE key_text=?",(key,)).fetchall()]
    if device not in devs and len(devs) >= 2:
        conn.close()
        return jsonify({"ok": False, "error": "room full (2 devices max)"}), 403
    # insert or update device
    cur.execute("SELECT id FROM devices WHERE device_id=? AND key_text=?", (device, key))
    if cur.fetchone():
        cur.execute("UPDATE devices SET name=?, last_seen=? WHERE device_id=? AND key_text=?", (name, int(time.time()), device, key))
    else:
        cur.execute("INSERT INTO devices (device_id,key_text,name,last_seen) VALUES (?,?,?,?)", (device, key, name, int(time.time())))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/api/send", methods=["POST"])
def send_msg():
    data = request.json or {}
    key = (data.get("key") or "").strip()
    device = (data.get("device_id") or "").strip()
    name = (data.get("name") or "").strip()
    mtype = data.get("type","text")
    content = data.get("content","")
    if not key or not device:
        return jsonify({"ok": False, "error": "missing"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("INSERT INTO messages (key_text,device_id,name,type,content,ts) VALUES (?,?,?,?,?,?)", (key, device, name, mtype, content, int(time.time())))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/api/messages", methods=["GET"])
def get_messages():
    key = request.args.get("key","").strip()
    since = int(request.args.get("since","0"))
    if not key:
        return jsonify({"ok": False, "error": "missing key"}), 400
    conn = get_db(); cur = conn.cursor()
    rows = cur.execute("SELECT id,device_id,name,type,content,ts FROM messages WHERE key_text=? AND ts>=? ORDER BY ts ASC", (key, since)).fetchall()
    out = [dict(r) for r in rows]
    conn.close()
    return jsonify({"ok": True, "messages": out})

@app.route("/api/devices", methods=["GET"])
def list_devices():
    key = request.args.get("key","").strip()
    if not key:
        return jsonify({"ok": False, "error": "missing key"}), 400
    conn = get_db(); cur = conn.cursor()
    rows = cur.execute("SELECT device_id,name,last_seen FROM devices WHERE key_text=?", (key,)).fetchall()
    out = [dict(r) for r in rows]
    conn.close()
    return jsonify({"ok": True, "devices": out})

@app.route("/api/ping", methods=["POST"])
def ping_device():
    data = request.json or {}
    device = (data.get("device_id") or "").strip()
    key = (data.get("key") or "").strip()
    if not device or not key:
        return jsonify({"ok": False, "error": "missing"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE devices SET last_seen=? WHERE device_id=? AND key_text=?", (int(time.time()), device, key))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

# --- Serve UI ---
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

if __name__ == "__main__":
    print("Starting PVT server on http://127.0.0.1:5000")
    app.run(debug=True)
