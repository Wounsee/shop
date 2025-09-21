# multi.py
import os
import json
import uuid
import time
import hmac
import hashlib
import threading
import pathlib

from flask import Flask, jsonify, request, send_from_directory, url_for
from flask_cors import CORS
import requests

UPLOAD_DIR = 'uploads'
DATA_FILE = 'products.json'

# ---------------- CONFIG ----------------
# Admin password (по твоей просьбе — жестко заданный)
ADMIN_PASSWORD = '123'   # <- пароль администратора
# Telegram related (optional, but keep)
BOT_TOKEN = os.environ.get('FC_BOT_TOKEN', '')
STARTUP_CHAT_ID = os.environ.get('FC_STARTUP_CHAT_ID', '')
# Admin IDs via env (optional telegram-based admin)
ADMIN_IDS = set(int(x) for x in os.environ.get('FC_ADMIN_IDS', '').split(',') if x.strip().isdigit())
INITDATA_TTL = int(os.environ.get('FC_INITDATA_TTL', '3600'))
# ----------------------------------------

app = Flask(__name__, static_folder='.')
CORS(app)

def ensure_files():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'products': [], 'categories': []}, f, ensure_ascii=False, indent=2)
    os.makedirs(UPLOAD_DIR, exist_ok=True)

def load_data():
    ensure_files()
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def save_upload(file_storage):
    ensure_files()
    fname = file_storage.filename or ''
    ext = ''
    if '.' in fname:
        ext = '.' + fname.rsplit('.', 1)[1]
    newname = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(UPLOAD_DIR, newname)
    file_storage.save(path)
    return url_for('uploaded_file', filename=newname, _external=False)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# ---------- initData verify functions (unchanged) ----------
def parse_query_string(qs):
    params = {}
    if not qs:
        return params
    if qs.startswith('?'):
        qs = qs[1:]
    for part in qs.split('&'):
        if not part:
            continue
        if '=' in part:
            k, v = part.split('=', 1)
            try:
                from urllib.parse import unquote_plus
                v_dec = unquote_plus(v)
            except:
                v_dec = v
            params[k] = v_dec
        else:
            params[part] = ''
    return params

def compute_hash(params, bot_token):
    items = []
    for k in sorted(params.keys()):
        items.append(f"{k}={params[k]}")
    data_check_string = '\n'.join(items)
    secret = hmac.new(b'WebAppData', bot_token.encode('utf-8'), hashlib.sha256).digest()
    computed = hmac.new(secret, data_check_string.encode('utf-8'), hashlib.sha256).hexdigest()
    return computed

def verify_initdata(initdata_raw, bot_token):
    if not initdata_raw:
        return False, 'missing initData'
    if not bot_token:
        return False, 'server has no BOT_TOKEN'
    try:
        params = parse_query_string(initdata_raw)
        if 'hash' not in params or 'auth_date' not in params:
            return False, 'missing hash/auth_date'
        provided_hash = params.pop('hash')
        computed = compute_hash(params, bot_token)
        if not hmac.compare_digest(computed, provided_hash):
            return False, 'hash mismatch'
        try:
            auth_date = int(params.get('auth_date', '0'))
            if abs(time.time() - auth_date) > INITDATA_TTL:
                return False, 'auth_date expired'
        except:
            return False, 'bad auth_date'
        user = {}
        if 'user' in params:
            try:
                user = json.loads(params['user'])
            except:
                if params['user'].isdigit():
                    user = {'id': int(params['user'])}
                else:
                    user = {'raw': params['user']}
        elif 'user_id' in params and params['user_id'].isdigit():
            user = {'id': int(params['user_id'])}
        return True, user
    except Exception as e:
        return False, f'exception {e}'

def extract_initdata(req):
    auth = req.headers.get('Authorization') or req.headers.get('authorization') or ''
    if auth.startswith('tma '):
        return auth[4:]
    try:
        j = req.get_json(silent=True)
        if j and 'initData' in j:
            return j['initData']
    except:
        pass
    if 'initData' in req.form:
        return req.form.get('initData')
    return None

# new: check admin either by initData (telegram) OR by admin password (header/form/json)
def is_request_admin(req):
    # 1) check explicit admin password in header
    header_pw = (req.headers.get('X-Admin-Pass') or req.headers.get('X-Admin-Pass'.lower()) or '').strip()
    if header_pw and header_pw == ADMIN_PASSWORD:
        return True, {'id': 'pw-admin'}
    # 2) check in json body
    try:
        j = req.get_json(silent=True)
        if j and isinstance(j, dict) and j.get('admin_pass') == ADMIN_PASSWORD:
            return True, {'id': 'pw-admin'}
    except:
        pass
    # 3) check form field (multipart)
    if 'admin_pass' in req.form and req.form.get('admin_pass') == ADMIN_PASSWORD:
        return True, {'id': 'pw-admin'}
    # 4) fallback to initData verification if BOT_TOKEN present
    init_raw = extract_initdata(req)
    ok, user_or_err = verify_initdata(init_raw, BOT_TOKEN) if BOT_TOKEN else (False, 'no BOT_TOKEN configured')
    if not ok:
        return False, user_or_err
    user = user_or_err
    uid = user.get('id') if isinstance(user, dict) else None
    if uid and int(uid) in ADMIN_IDS:
        return True, user
    return False, user

# ---------- API endpoints (products, categories, upload, verify) ----------
@app.route('/api/products', methods=['GET'])
def api_products():
    data = load_data()
    return jsonify({'products': data.get('products', [])})

@app.route('/api/product', methods=['POST'])
def api_add_product():
    is_admin, info = is_request_admin(request)
    if not is_admin:
        return jsonify({'error': 'unauthorized', 'info': str(info)}), 401
    # accept form or json
    payload = request.form.to_dict() if request.form else (request.get_json(silent=True) or {})
    title = payload.get('title')
    price = payload.get('price')
    category = payload.get('category', '')
    description = payload.get('description', '')
    image = payload.get('image', '')
    if 'image_file' in request.files:
        image = save_upload(request.files['image_file'])
    if not title or price is None:
        return jsonify({'error': 'title and price required'}), 400
    data = load_data()
    new = {
        'id': str(uuid.uuid4()),
        'title': title,
        'price': float(price),
        'description': description,
        'image': image,
        'category': category
    }
    data.setdefault('products', []).append(new)
    save_data(data)
    return jsonify({'ok': True, 'product': new})

@app.route('/api/product/<pid>', methods=['DELETE'])
def api_delete_product(pid):
    is_admin, info = is_request_admin(request)
    if not is_admin:
        return jsonify({'error': 'unauthorized', 'info': str(info)}), 401
    data = load_data()
    before = len(data.get('products', []))
    data['products'] = [p for p in data.get('products', []) if p.get('id') != pid]
    save_data(data)
    return jsonify({'ok': True, 'removed': before - len(data.get('products', []))})

@app.route('/api/verify', methods=['POST'])
def api_verify():
    # Accept admin password or initData for verify
    # If admin_pass present, treat as admin
    admin_pass = None
    header_pw = request.headers.get('X-Admin-Pass') or request.headers.get('X-Admin-Pass'.lower())
    if header_pw:
        admin_pass = header_pw
    else:
        try:
            j = request.get_json(silent=True)
            if j and 'admin_pass' in j:
                admin_pass = j.get('admin_pass')
        except:
            pass
    if admin_pass == ADMIN_PASSWORD:
        return jsonify({'ok': True, 'user': {'id': 'pw-admin'}, 'is_admin': True})
    # else fallback to initData verify
    init_raw = extract_initdata(request)
    ok, user_or_err = verify_initdata(init_raw, BOT_TOKEN) if BOT_TOKEN else (False, 'no BOT_TOKEN configured')
    if not ok:
        return jsonify({'ok': False, 'error': user_or_err}), 400
    user = user_or_err
    is_admin = (user.get('id') and int(user.get('id')) in ADMIN_IDS)
    return jsonify({'ok': True, 'user': user, 'is_admin': bool(is_admin)})

@app.route('/api/categories', methods=['GET'])
def api_categories():
    data = load_data()
    return jsonify({'categories': data.get('categories', [])})

@app.route('/api/category', methods=['POST'])
def api_add_category():
    is_admin, info = is_request_admin(request)
    if not is_admin:
        return jsonify({'error': 'unauthorized', 'info': str(info)}), 401
    payload = request.get_json(silent=True) or request.form.to_dict() or {}
    name = payload.get('name')
    if not name:
        return jsonify({'error': 'name required'}), 400
    data = load_data()
    cid = str(uuid.uuid4())
    data.setdefault('categories', []).append({'id': cid, 'name': name})
    save_data(data)
    return jsonify({'ok': True, 'category': {'id': cid, 'name': name}})

@app.route('/api/category/<cid>', methods=['DELETE'])
def api_delete_category(cid):
    is_admin, info = is_request_admin(request)
    if not is_admin:
        return jsonify({'error': 'unauthorized', 'info': str(info)}), 401
    data = load_data()
    before = len(data.get('categories', []))
    data['categories'] = [c for c in data.get('categories', []) if c.get('id') != cid]
    save_data(data)
    return jsonify({'ok': True, 'removed': before - len(data.get('categories', []))})

@app.route('/api/upload', methods=['POST'])
def api_upload():
    # accept admin via header/form/json or initData
    is_admin, info = is_request_admin(request)
    if not is_admin:
        return jsonify({'error': 'unauthorized', 'info': str(info)}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'file missing'}), 400
    f = request.files['file']
    url = save_upload(f)
    return jsonify({'ok': True, 'url': url})

# ---------- Telegram bot: simple /start ----------
def send_startup():
    if not BOT_TOKEN or not STARTUP_CHAT_ID:
        print("Startup notify skipped.")
        return
    try:
        text = f"FunnyCloud server started. Host: {os.environ.get('HOSTNAME','local')}"
        r = requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json={'chat_id': STARTUP_CHAT_ID, 'text': text}, timeout=10)
        if r.ok: print("Startup notify sent")
        else: print("Startup notify failed", r.status_code, r.text)
    except Exception as e:
        print("Startup notify error", e)

def start_bot():
    if not BOT_TOKEN:
        print("No BOT_TOKEN, bot not started.")
        return
    try:
        from telegram.ext import Updater, CommandHandler
    except Exception as e:
        print("python-telegram-bot not installed or import failed:", e)
        return
    def on_start(update, context):
        uid = update.effective_user.id
        if uid and uid in ADMIN_IDS:
            context.bot.send_message(chat_id=uid, text="Привет, админ. Бот работает.")
        else:
            context.bot.send_message(chat_id=uid, text="Бот запущен. Магазин FunnyCloud работает.")
    try:
        updater = Updater(BOT_TOKEN, use_context=True)
        dp = updater.dispatcher
        dp.add_handler(CommandHandler('start', on_start))
        updater.start_polling()
        print("Telegram bot started (polling).")
    except Exception as e:
        print("Failed to start bot:", e)

# ---------- runner ----------
if __name__ == '__main__':
    ensure_files = lambda: None
    # ensure files + uploads
    ensure_files()
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'products': [], 'categories': []}, f, ensure_ascii=False, indent=2)
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # start bot thread + startup notify
    try:
        threading.Thread(target=start_bot, daemon=True).start()
        threading.Thread(target=send_startup, daemon=True).start()
    except Exception as e:
        print("Bot/startup thread error:", e)

    port = int(os.environ.get('PORT', '5000'))
    print(f"Starting Flask on 0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)
