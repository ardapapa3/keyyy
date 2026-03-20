"""
api_server.py  —  Railway'e yüklenecek lisans doğrulama sunucusu
Kurulum:
  pip install flask cryptography
Çalıştır (local test):
  python api_server.py
"""

import os
import hashlib
import sqlite3
import json
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet

# ─── AYARLAR ──────────────────────────────────────────────────────────────────
MASTER_PASSWORD = os.environ.get("MASTER_PASSWORD", "MySuperSecretMasterPassword123!@#")
ENCRYPTION_KEY  = os.environ.get("ENCRYPTION_KEY",  "12345678901234567890123456789012").encode()
API_SECRET      = os.environ.get("API_SECRET",      "gizli-api-anahtari-bunu-degistir")
DB_FILE         = os.environ.get("DB_FILE",         "license_keys.db")
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)


def get_cipher():
    key_32 = ENCRYPTION_KEY.ljust(32, b'0')[:32]
    return Fernet(base64.urlsafe_b64encode(key_32))


def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash     TEXT UNIQUE,
            key_data     TEXT,
            created_date TEXT,
            expiry_date  TEXT,
            is_active    INTEGER DEFAULT 1
        )
    ''')
    conn.commit()
    conn.close()


init_db()


# ── YARDIMCI ──────────────────────────────────────────────────────────────────
def check_api_secret(req):
    return req.headers.get("X-API-Secret") == API_SECRET


# ── ENDPOINT 1: Lisans doğrula (exe bu endpoint'i kullanır) ───────────────────
@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(force=True, silent=True) or {}
    key  = str(data.get("key", "")).strip().upper()

    if not key:
        return jsonify({"valid": False, "message": "Anahtar boş."}), 400

    key_hash = hashlib.sha256(key.encode()).hexdigest()

    conn = sqlite3.connect(DB_FILE)
    row  = conn.execute(
        "SELECT key_data, expiry_date, is_active FROM licenses WHERE key_hash=?",
        (key_hash,)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"valid": False, "message": "Geçersiz lisans anahtarı."})

    key_data_enc, expiry_str, is_active = row

    if not is_active:
        return jsonify({"valid": False, "message": "Bu lisans iptal edilmiş."})

    try:
        cipher   = get_cipher()
        key_data = json.loads(cipher.decrypt(key_data_enc.encode()).decode())
        key_id   = key_data["key_id"]
        expected = hashlib.sha256(f"{key_id}{MASTER_PASSWORD}".encode()).hexdigest()[:32]
        if key_data["signature"] != expected:
            return jsonify({"valid": False, "message": "Lisans bozuk."})
    except Exception:
        return jsonify({"valid": False, "message": "Lisans verisi okunamadı."})

    try:
        expiry = datetime.fromisoformat(expiry_str)
        if datetime.now() > expiry:
            return jsonify({"valid": False, "message": f"Lisans süresi dolmuş. ({expiry.strftime('%d.%m.%Y')})"})
    except Exception:
        return jsonify({"valid": False, "message": "Tarih okunamadı."})

    return jsonify({"valid": True, "message": "Lisans geçerli.", "expiry": expiry.strftime("%d.%m.%Y")})


# ── ENDPOINT 2: Key üret (generator GUI bu endpoint'i kullanır) ───────────────
@app.route("/generate", methods=["POST"])
def generate():
    if not check_api_secret(request):
        return jsonify({"error": "Yetkisiz erişim."}), 403

    data       = request.get_json(force=True, silent=True) or {}
    days_valid = int(data.get("days", 365))
    count      = max(1, min(100, int(data.get("count", 1))))

    import random, string as _string
    generated = []

    for _ in range(count):
        segments = [''.join(random.choices(_string.ascii_uppercase + _string.digits, k=4)) for _ in range(4)]
        key      = '-'.join(segments)
        key_id   = hashlib.md5(key.encode()).hexdigest()[:8]
        sig      = hashlib.sha256(f"{key_id}{MASTER_PASSWORD}".encode()).hexdigest()[:32]
        key_data = {"key_id": key_id, "created": datetime.now().isoformat(),
                    "expiry_days": days_valid, "signature": sig}
        cipher   = get_cipher()
        enc      = cipher.encrypt(json.dumps(key_data).encode()).decode()
        khash    = hashlib.sha256(key.encode()).hexdigest()
        now      = datetime.now()
        expiry   = now + timedelta(days=days_valid)

        conn = sqlite3.connect(DB_FILE)
        try:
            conn.execute(
                "INSERT INTO licenses (key_hash,key_data,created_date,expiry_date,is_active) VALUES (?,?,?,?,?)",
                (khash, enc, now.isoformat(), expiry.isoformat(), 1)
            )
            conn.commit()
            generated.append({"key": key, "expiry": expiry.strftime("%d.%m.%Y")})
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()

    return jsonify({"generated": generated, "count": len(generated)})


# ── ENDPOINT 3: Tüm lisansları listele ────────────────────────────────────────
@app.route("/list", methods=["GET"])
def list_keys():
    if not check_api_secret(request):
        return jsonify({"error": "Yetkisiz erişim."}), 403

    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT id, key_hash, created_date, expiry_date, is_active FROM licenses ORDER BY id DESC"
    ).fetchall()
    conn.close()

    keys = []
    for row in rows:
        rid, khash, created, expiry, active = row
        try:
            expired = datetime.fromisoformat(expiry) < datetime.now()
        except Exception:
            expired = False
        status = "iptal" if not active else ("suresi_dolmus" if expired else "aktif")
        keys.append({
            "id":      rid,
            "hash":    khash[:16] + "…",
            "created": created[:16],
            "expiry":  expiry[:10],
            "status":  status
        })

    return jsonify({"keys": keys, "total": len(keys)})


# ── ENDPOINT 4: İptal et ──────────────────────────────────────────────────────
@app.route("/revoke", methods=["POST"])
def revoke():
    if not check_api_secret(request):
        return jsonify({"error": "Yetkisiz erişim."}), 403

    data   = request.get_json(force=True, silent=True) or {}
    row_id = data.get("id")
    if row_id is None:
        return jsonify({"error": "id gerekli."}), 400

    conn = sqlite3.connect(DB_FILE)
    conn.execute("UPDATE licenses SET is_active=0 WHERE id=?", (row_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"#{row_id} iptal edildi."})


# ── ENDPOINT 5: Aktif et ──────────────────────────────────────────────────────
@app.route("/activate", methods=["POST"])
def activate():
    if not check_api_secret(request):
        return jsonify({"error": "Yetkisiz erişim."}), 403

    data   = request.get_json(force=True, silent=True) or {}
    row_id = data.get("id")
    if row_id is None:
        return jsonify({"error": "id gerekli."}), 400

    conn = sqlite3.connect(DB_FILE)
    conn.execute("UPDATE licenses SET is_active=1 WHERE id=?", (row_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"#{row_id} aktif edildi."})


# ── ENDPOINT 6: Sil ───────────────────────────────────────────────────────────
@app.route("/delete", methods=["POST"])
def delete_key():
    if not check_api_secret(request):
        return jsonify({"error": "Yetkisiz erişim."}), 403

    data   = request.get_json(force=True, silent=True) or {}
    row_id = data.get("id")
    if row_id is None:
        return jsonify({"error": "id gerekli."}), 400

    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM licenses WHERE id=?", (row_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"#{row_id} silindi."})


# ── Sağlık kontrolü ───────────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "License API"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
