# multi.py
# Flask backend + Telegram bot in one file.
# Endpoints:
#  /                 -> index.html
#  /api/products     -> GET products
#  /api/product      -> POST add product (admin)
#  /api/product/<id> -> DELETE product (admin)
#  /api/verify       -> POST verify initData
#  /api/categories   -> GET categories
#  /api/category     -> POST add category (admin), DELETE /api/category/<id> (admin)
#  /api/upload       -> POST file upload (admin)
#
# Environment variables (set in Render or your host):
#   FC_BOT_TOKEN        - token для telegram бота (опционально, нужен для verify и startup notify)
#   FC_ADMIN_IDS        - comma separated admin ids (например "123456,987654")
#   FC_STARTUP_CHAT_ID  - (optional) chat id для отправки стартового уведомления
#   PORT                - Render-provided port (скрипт использует по умолчанию 5000)
#
# requirements: flask, flask-cors, requests, python-telegram-bot==13.15

import os
import io
import json
import uuid
import time
import hmac
import hashlib
import threading
import pathlib
from typing import Tuple

from flask import Flask, jsonify, request, send_from_directory, abort, url_for
from flask_cors import CORS
import requests

UPLOAD_DIR = 'uploads'
DATA_FILE = 'products.json'

# Read env vars
BOT_TOKEN = os.environ.get('FC_BOT_TOKEN', '')              # если пусто — верификация невозможна, админка не появится
ADMIN_IDS = set(int(x) for x in os.environ.get('FC_ADMIN_IDS', '').split(',') if x.strip().isdigit())
STARTUP_CHAT_ID = os.environ.get('FC_STARTUP_CHAT_ID', '')
INITDATA_TTL = int(os.environ.get('FC_INITDATA_TTL', '3600'))

app = Flask(__name__, static_folder='.')
CORS(app)

# --- Helpers: products + categories + uploads ---
def ensure_data_file():
    if not os.path.exists(DATA_FILE):
        save_data({'products': [], 'categories': []})
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR, exist_ok=True)

def load_data():
    ensure_data_file()
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def save_upload_file(file_storage):
    """
    Save uploaded file (werkzeug FileStorage) to uploads directory and return public path.
    """
    ensure_data_file()
    fname = file_storage.filename or ''
    ext = ''
    if '.' in fname:
        ext = '.' + fname.rsplit('.', 1)[1]
    newname = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(UPLOAD_DIR, newname)
    file_storage.save(path)
    return url_for('uploaded_file', filename=newname, _external=False)  # relative url

# --- InitData verification (Telegram WebApp) ---
# Robust parsing: accepts URL-encoded values; handles 'user' as JSON or numeric id.
def parse_query_string(qs: str) -> dict:
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
            # values from WebApp often URL-encoded
            try:
                from urllib.parse import unquote_plus
                v_dec = unquote_plus(v)
            except:
                v_dec = v
            params[k] = v_dec
        else:
            params[part] = ''
    return params

def compute_initdata_hash(params: dict, bot_token: str) -> Tuple[bool, str]:
    # Build data_check_string from params (params must NOT include 'hash')
    items = []
    for k in sorted(params.keys()):
        items.append(f"{k}={params[k]}")
    data_check_string = '\n'.join(items)
    # secret = HMAC_SHA256(key=b"WebAppData", msg=bot_token)
    secret = hmac.new(b'WebAppData', bot_token.encode('utf-8'), hashlib.sha256).digest()
    computed_hash = hmac.new(secret, data_check_string.encode('utf-8'), hashlib.sha256).hexdigest()
    return True, computed_hash

def verify_initdata(initdata_raw: str, bot_token: str):
    """
    Returns (ok: bool, user_or_error)
    """
    if not initdata_raw:
        return False, 'missing initData'
    if not bot_token:
        return False, 'server has no BOT_TOKEN for verification'
    try:
        params = parse_query_string(initdata_raw)
        if 'hash' not in params or 'auth_date' not in params:
            return False, 'missing hash or auth_date'
        provided_hash = params.pop('hash')
        # compute hash
        ok, computed = compute_initdata_hash(params, bot_token)
        if not ok:
            return False, 'compute error'
        # timing-safe compare (hex strings)
        if not hmac.compare_digest(computed, provided_hash):
            return False, 'hash mismatch'
        # check auth_date fresh
        try:
            auth_date = int(params.get('auth_date', '0'))
            if abs(time.time() - auth_date) > INITDATA_TTL:
                return False, 'auth_date expired'
        except:
            return False, 'bad auth_date'
        # parse user
        user = {}
        if 'user' in params:
            try:
                user = json.loads(params['user'])
            except:
                # fallback numeric
                if params['user'].isdigit():
                    user = {'id': int(params['user'])}
                else:
                    user = {'raw': params['user']}
        elif 'user_id' in params and params['user_id'].isdigit():
            user = {'id': int(params['user_id'])}
        return True, user
    except Exception as e:
        return False, f'exception {e}'

def extract_initdata_from_request(req):
    # 1) header Authorization: tma <raw>
    auth = req.headers.get('Authorization') or req.headers.get('authorization') or ''
    if auth.startswith('tma '):
        return auth[4:]
    # 2) JSON body field initData
    try:
        j = req.get_json(silent=True)
        if j and 'initData' in j:
            return j['initData']
    except:
        pass
    # 3) form field (multipart/form-data) named initData
    if 'initData' in req.form:
        return req.form.get('initData')
    return None

def is_request_admin(req):
    init_raw = extract_initdata_from_request(req)
    ok, user_or_err = verify_initdata(init_raw, BOT_TOKEN)
    if not ok:
        return False, user_or_err
    user = user_or_err
    uid = user.get('id') if isinstance(user, dict) else None
    if uid and int(uid) in ADMIN_IDS:
        return True, user
    return False, user

# --- Routes ---
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

@app.route('/api/products', methods=['GET'])
def api_products():
    data = load_data()
    return jsonify({'products': data.get('products', [])})

@app.route('/api/product', methods=['POST'])
def api_add_product():
    ok_admin, info = is_request_admin(request)
    if not ok_admin:
        return jsonify({'error': 'unauthorized', 'info': str(info)}), 401
    payload = request.form.to_dict() if request.form else (request.get_json(silent=True) or {})
    title = payload.get('title')
    price = payload.get('price')
    category = payload.get('category', '')
    description = payload.get('description', '')
    image = payload.get('image', '')
    if 'image_file' in request.files:
        # if file uploaded along with product (rare), save it
        path = save_upload_file(request.files['image_file'])
        image = path
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
    data['products'].append(new)
    # if category not exists, ignore (admin should create categories first)
    save_data(data)
    return jsonify({'ok': True, 'product': new})

@app.route('/api/product/<pid>', methods=['DELETE'])
def api_delete_product(pid):
    ok_admin, info = is_request_admin(request)
    if not ok_admin:
        return jsonify({'error': 'unauthorized', 'info': str(info)}), 401
    data = load_data()
    before = len(data['products'])
    data['products'] = [p for p in data['products'] if p.get('id') != pid]
    save_data(data)
    return jsonify({'ok': True, 'removed': before - len(data['products'])})

@app.route('/api/verify', methods=['POST'])
def api_verify():
    init_raw = extract_initdata_from_request(request)
    ok, user_or_err = verify_initdata(init_raw, BOT_TOKEN)
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
    ok_admin, info = is_request_admin(request)
    if not ok_admin:
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
    ok_admin, info = is_request_admin(request)
    if not ok_admin:
        return jsonify({'error': 'unauthorized', 'info': str(info)}), 401
    data = load_data()
    before = len(data.get('categories', []))
    data['categories'] = [c for c in data.get('categories', []) if c.get('id') != cid]
    save_data(data)
    return jsonify({'ok': True, 'removed': before - len(data.get('categories', []))})

@app.route('/api/upload', methods=['POST'])
def api_upload():
    ok_admin, info = is_request_admin(request)
    if not ok_admin:
        return jsonify({'error': 'unauthorized', 'info': str(info)}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'file missing'}), 400
    f = request.files['file']
    url = save_upload_file(f)
    return jsonify({'ok': True, 'url': url})

# --- Telegram bot (start message + /start handler) ---
def send_startup_notification():
    if not BOT_TOKEN or not STARTUP_CHAT_ID:
        print("Startup notify skipped (FC_BOT_TOKEN or FC_STARTUP_CHAT_ID not set).")
        return
    try:
        text = f"FunnyCloud server started. Host: {os.environ.get('HOSTNAME','local')}"
        resp = requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                             json={'chat_id': STARTUP_CHAT_ID, 'text': text}, timeout=10)
        if resp.ok:
            print("Startup notify sent")
        else:
            print("Startup notify failed:", resp.status_code, resp.text)
    except Exception as e:
        print("Startup notify error:", e)

def start_bot_background():
    if not BOT_TOKEN:
        print("FC_BOT_TOKEN empty — bot not started.")
        return
    try:
        from telegram.ext import Updater, CommandHandler
    except Exception as e:
        print("python-telegram-bot not installed or import failed:", e)
        return
    def on_start(update, context):
        uid = update.effective_user.id
        if uid in ADMIN_IDS:
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

# --- main runner ---
if __name__ == '__main__':
    ensure_data_file()
    # start bot in thread
    try:
        t = threading.Thread(target=start_bot_background, daemon=True)
        t.start()
        threading.Thread(target=send_startup_notification, daemon=True).start()
    except Exception as e:
        print("Bot/startup thread error:", e)

    port = int(os.environ.get('PORT', '5000'))
    print(f"Starting Flask on 0.0.0.0:{port}")
    # debug False on host
    app.run(host='0.0.0.0', port=port, debug=False)
