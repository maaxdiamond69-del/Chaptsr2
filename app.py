from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import os
from datetime import datetime, timedelta
import threading
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from supabase import create_client, Client
import logging
import schedule

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-this-in-production'

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Supabase configuration
SUPABASE_URL = "https://tmzvxcujrglyrvpnycul.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRtenZ4Y3VqcmdseXJ2cG55Y3VsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODA2MzMwMDUsImV4cCI6MjA5NjIwOTAwNX0.egPtT_hbjdAUC4_Dja_c1ES27I89BUr97rDaMWMQdGI"

# Global Supabase client
supabase = None

# Auto-refresh interval (6 hours in seconds)
AUTO_REFRESH_INTERVAL = 6 * 60 * 60  # 21600 seconds

# Track auto-refresh status
auto_refresh_status = {}
auto_refresh_lock = threading.Lock()

# Thread pool for concurrent operations
MAX_WORKERS = 50
thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# JWT APIs for token generation
JWT_APIS = [
    "https://regiiister-sgsgsg-half.vercel.app/get-token",
    "https://lol-ari-gay-ka-major-register-sgg.vercel.app/get-token",
    "https://register-sggg-half.vercel.app/get-token",
    "https://register-ssssggg-half.vercel.app/get-token",
    "https://register-guest-bd.vercel.app/get-token",
    "https://ari-gay-jwt.vercel.app/get-token",
    "https://ariflexlabs-jwt.vercel.app/get-token",
    "https://jwt-generate-saygex.vercel.app/get-token",
    "https://jwt-gen-aripydev.vercel.app/get-token"
]

def create_supabase_client():
    """Create and test Supabase client connection"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            client = create_client(SUPABASE_URL, SUPABASE_KEY)
            client.table("users").select("*").limit(1).execute()
            logger.info("Supabase connection successful")
            return client
        except Exception as e:
            logger.warning(f"Supabase connection attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(2)
            else:
                logger.error("All Supabase connection attempts failed")
                raise

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

# Supabase CRUD Operations
def get_user_by_username(username):
    try:
        response = supabase.table("users").select("*").eq("username", username).execute()
        if response.data:
            return response.data[0]
        return None
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        return None

def get_user_by_id(user_id):
    try:
        response = supabase.table("users").select("*").eq("id", user_id).execute()
        if response.data:
            return response.data[0]
        return None
    except Exception as e:
        logger.error(f"Error getting user by ID: {e}")
        return None

def create_user(username, password_hash):
    try:
        response = supabase.table("users").insert({
            "username": username,
            "password_hash": password_hash
        }).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return None

def get_user_keys(username):
    try:
        response = supabase.table("api_keys").select("*").eq("username", username).execute()
        keys = {}
        for key in response.data:
            keys[key['api_key']] = {
                'key': key['api_key'],
                'uid_count': key.get('uid_count', 0),
                'token_count': key.get('token_count', 0),
                'created_at': key.get('created_at', ''),
                'last_refresh': key.get('last_refresh', ''),
                'successful_uids': key.get('successful_uids', 0),
                'failed_uids': key.get('failed_uids', 0),
                'auto_refresh': key.get('auto_refresh', True)
            }
        return keys
    except Exception as e:
        logger.error(f"Error getting user keys: {e}")
        return {}

def get_all_api_keys():
    """Get all API keys from all users for auto-refresh"""
    try:
        response = supabase.table("api_keys").select("*").execute()
        return response.data
    except Exception as e:
        logger.error(f"Error getting all API keys: {e}")
        return []

def create_api_key(username, api_key, uid_count=0):
    try:
        response = supabase.table("api_keys").insert({
            "username": username,
            "api_key": api_key,
            "uid_count": uid_count,
            "token_count": 0,
            "successful_uids": 0,
            "failed_uids": 0,
            "auto_refresh": True
        }).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        return None

def save_uids_batch(api_key, username, uid_data):
    try:
        supabase.table("uids").delete().eq("api_key", api_key).execute()
        batch_size = 100
        uid_list = [{"api_key": api_key, "username": username, "uid": uid, "password": pwd} 
                    for uid, pwd in uid_data.items()]
        for i in range(0, len(uid_list), batch_size):
            batch = uid_list[i:i + batch_size]
            supabase.table("uids").insert(batch).execute()
        return True
    except Exception as e:
        logger.error(f"Error saving UIDs: {e}")
        return False

def get_uids_for_key(api_key):
    try:
        response = supabase.table("uids").select("uid, password").eq("api_key", api_key).execute()
        uid_dict = {}
        for item in response.data:
            uid_dict[item['uid']] = item['password']
        return uid_dict
    except Exception as e:
        logger.error(f"Error getting UIDs: {e}")
        return {}

def get_uid_count(api_key):
    try:
        response = supabase.table("uids").select("id", count="exact").eq("api_key", api_key).execute()
        return response.count if response.count else 0
    except:
        return 0

def save_tokens_batch(api_key, username, tokens_data):
    try:
        supabase.table("tokens").update({"status": "inactive"}).eq("api_key", api_key).eq("status", "active").execute()
        batch_size = 100
        token_list = [{"api_key": api_key, "username": username, "uid": uid, "token": token, "status": "active"} 
                     for uid, token in tokens_data]
        for i in range(0, len(token_list), batch_size):
            batch = token_list[i:i + batch_size]
            supabase.table("tokens").insert(batch).execute()
        return True
    except Exception as e:
        logger.error(f"Error saving tokens: {e}")
        return False

def get_active_tokens(api_key):
    try:
        response = supabase.table("tokens").select("token").eq("api_key", api_key).eq("status", "active").execute()
        return [item['token'] for item in response.data]
    except Exception as e:
        logger.error(f"Error getting tokens: {e}")
        return []

def get_token_count(api_key):
    try:
        response = supabase.table("tokens").select("id", count="exact").eq("api_key", api_key).eq("status", "active").execute()
        return response.count if response.count else 0
    except:
        return 0

def update_api_key_stats(api_key, token_count, success_count, fail_count):
    try:
        supabase.table("api_keys").update({
            "token_count": token_count,
            "successful_uids": success_count,
            "failed_uids": fail_count,
            "last_refresh": datetime.now().isoformat()
        }).eq("api_key", api_key).execute()
        
        # Update auto-refresh tracking
        with auto_refresh_lock:
            auto_refresh_status[api_key] = {
                'last_refresh': datetime.now(),
                'next_refresh': datetime.now() + timedelta(seconds=AUTO_REFRESH_INTERVAL)
            }
        
        return True
    except Exception as e:
        logger.error(f"Error updating key stats: {e}")
        return False

def set_auto_refresh(api_key, enabled):
    """Enable or disable auto-refresh for a key"""
    try:
        supabase.table("api_keys").update({
            "auto_refresh": enabled
        }).eq("api_key", api_key).execute()
        return True
    except Exception as e:
        logger.error(f"Error setting auto-refresh: {e}")
        return False

def delete_api_key(api_key):
    try:
        supabase.table("tokens").delete().eq("api_key", api_key).execute()
        supabase.table("uids").delete().eq("api_key", api_key).execute()
        supabase.table("api_keys").delete().eq("api_key", api_key).execute()
        
        # Remove from auto-refresh tracking
        with auto_refresh_lock:
            if api_key in auto_refresh_status:
                del auto_refresh_status[api_key]
        
        return True
    except Exception as e:
        logger.error(f"Error deleting API key: {e}")
        return False

def find_user_by_api_key(api_key):
    try:
        response = supabase.table("api_keys").select("username").eq("api_key", api_key).execute()
        if response.data:
            return response.data[0]['username']
        return None
    except:
        return None

@login_manager.user_loader
def load_user(user_id):
    user_data = get_user_by_id(user_id)
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['password_hash'])
    return None

# Encryption and protobuf functions (keep existing)
def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%' 
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()

async def send_single_like(session, encrypted_uid, token, url, semaphore):
    async with semaphore:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54"
        }
        
        for retry in range(3):
            try:
                async with session.post(url, data=edata, headers=headers, timeout=30) as response:
                    if response.status == 503:
                        logger.warning(f"503 for token {token[:10]}..., retry {retry+1}/3")
                        await asyncio.sleep(1 * (retry + 1))
                        continue
                    return {"token": token[:10], "status": response.status, "success": response.status == 200}
            except Exception as e:
                logger.error(f"Error for token {token[:10]}...: {e}")
                await asyncio.sleep(0.5)
        
        return {"token": token[:10], "status": 503, "success": False}

async def send_all_likes_batch(uid, server_name, url, tokens):
    region = server_name
    protobuf_message = create_protobuf_message(uid, region)
    encrypted_uid = encrypt_message(protobuf_message)
    
    semaphore = asyncio.Semaphore(20)
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for token in tokens:
            tasks.append(send_single_like(session, encrypted_uid, token, url, semaphore))
        
        results = []
        for i, task in enumerate(tasks):
            if i > 0 and i % 50 == 0:
                await asyncio.sleep(1)
            results.append(await task)
    
    return results

def create_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = int(uid)
    message.garena = 1
    return message.SerializeToString()

def enc(uid):
    protobuf_data = create_protobuf(uid)
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypt)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB54"
    }
    
    for retry in range(3):
        try:
            response = requests.post(url, data=edata, headers=headers, verify=False, timeout=15)
            if response.status_code == 503:
                logger.warning(f"503 on profile check, retry {retry+1}/3")
                time.sleep(1 * (retry + 1))
                continue
            if response.status_code == 200 and len(response.content) > 0:
                hex_data = response.content.hex()
                binary = bytes.fromhex(hex_data)
                decode = decode_protobuf(binary)
                if decode is not None:
                    return decode
        except Exception as e:
            logger.error(f"Profile request error: {e}")
            time.sleep(0.5)
    
    return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        logger.error(f"Error decoding Protobuf data: {e}")
        return None

def fetch_token_for_uid(uid, password):
    session = requests.Session()
    for api_url in JWT_APIS:
        try:
            response = session.get(
                f"{api_url}?uid={uid}&password={password}", 
                timeout=5,
                headers={'Connection': 'close'}
            )
            if response.status_code == 200:
                response_data = response.json()
                token = response_data.get("response", "").split("token: ")[1].split("\n")[0].strip('"')
                if token:
                    session.close()
                    return token
        except:
            continue
    session.close()
    return None

def fetch_tokens_batch(uids_batch):
    results = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_uid = {
            executor.submit(fetch_token_for_uid, uid, password): uid 
            for uid, password in uids_batch
        }
        for future in as_completed(future_to_uid):
            uid = future_to_uid[future]
            try:
                token = future.result()
                results[uid] = token
            except:
                results[uid] = None
    return results

def refresh_tokens_for_key_fast(api_key, username):
    """FAST token refresh using parallel processing with Supabase"""
    uid_data = get_uids_for_key(api_key)
    
    if not uid_data:
        return False, "No UIDs configured for this key"
    
    uid_list = list(uid_data.items())
    total_uids = len(uid_list)
    
    batch_size = 50
    all_tokens = []
    successful_uids = []
    failed_uids = []
    failed_uid_passwords = []  # Store failed UID:password pairs
    
    start_time = time.time()
    
    print(f"\n{'='*60}")
    print(f"🔄 TOKEN REFRESH STARTED - Key: {api_key}")
    print(f"📊 Total UIDs: {total_uids}")
    print(f"{'='*60}")
    
    for i in range(0, total_uids, batch_size):
        batch = uid_list[i:i + batch_size]
        batch_results = fetch_tokens_batch(batch)
        
        for uid, token in batch_results.items():
            password = uid_data[uid]  # Get password for failed UID
            if token:
                all_tokens.append((uid, token))
                successful_uids.append(uid)
            else:
                failed_uids.append(uid)
                failed_uid_passwords.append({
                    "uid": uid,
                    "password": password
                })
    
    elapsed_time = time.time() - start_time
    
    # Print only failed UIDs
    if failed_uid_passwords:
        print(f"\n{'='*60}")
        print(f"❌ FAILED TOKEN GENERATION - {len(failed_uid_passwords)} UIDs:")
        print(f"{'='*60}")
        print(f"{'UID':<15} {'Password':<50}")
        print(f"{'-'*65}")
        for item in failed_uid_passwords:
            print(f"{item['uid']:<15} {item['password']:<50}")
        print(f"{'='*60}")
    else:
        print(f"✅ All {total_uids} UIDs processed successfully!")
    
    print(f"⏱️  Time: {elapsed_time:.2f}s | ✅ {len(successful_uids)} | ❌ {len(failed_uids)}")
    print(f"{'='*60}\n")
    
    if all_tokens:
        save_tokens_batch(api_key, username, all_tokens)
    
    update_api_key_stats(api_key, len(all_tokens), len(successful_uids), len(failed_uids))
    
    return True, {
        "total_uids": total_uids,
        "tokens_generated": len(all_tokens),
        "successful_uids": successful_uids,
        "failed_uids": failed_uids,
        "failed_uid_passwords": failed_uid_passwords,  # Include in return for flash messages
        "time_taken": f"{elapsed_time:.2f} seconds",
        "rate": f"{total_uids/elapsed_time:.1f} UIDs/second" if elapsed_time > 0 else "N/A"
    }

# Auto-refresh scheduler functions
def auto_refresh_all_keys():
    """Auto refresh tokens for all keys that need it"""
    logger.info("🔄 Starting auto-refresh check...")
    
    all_keys = get_all_api_keys()
    refreshed_count = 0
    
    for key_data in all_keys:
        api_key = key_data['api_key']
        username = key_data['username']
        auto_refresh = key_data.get('auto_refresh', True)
        last_refresh = key_data.get('last_refresh')
        
        # Skip if auto-refresh is disabled
        if not auto_refresh:
            continue
        
        # Check if refresh is needed (6 hours since last refresh)
        needs_refresh = True
        if last_refresh:
            try:
                last_refresh_time = datetime.fromisoformat(last_refresh.replace('Z', '+00:00'))
                time_since_refresh = (datetime.now() - last_refresh_time.replace(tzinfo=None)).total_seconds()
                if time_since_refresh < AUTO_REFRESH_INTERVAL:
                    needs_refresh = False
            except:
                pass
        
        if needs_refresh:
            logger.info(f"⏰ Auto-refreshing tokens for key: {api_key} (User: {username})")
            success, result = refresh_tokens_for_key_fast(api_key, username)
            if success:
                refreshed_count += 1
                logger.info(f"✅ Auto-refreshed {api_key}: {result['tokens_generated']} tokens")
            else:
                logger.error(f"❌ Failed to auto-refresh {api_key}: {result}")
    
    logger.info(f"🔄 Auto-refresh complete. Refreshed {refreshed_count} keys.")
    return refreshed_count

def run_scheduler():
    """Run the scheduler in a separate thread"""
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute

def get_time_until_next_refresh(api_key):
    """Get time remaining until next auto-refresh"""
    with auto_refresh_lock:
        if api_key in auto_refresh_status:
            next_refresh = auto_refresh_status[api_key]['next_refresh']
            time_left = next_refresh - datetime.now()
            if time_left.total_seconds() > 0:
                return str(time_left).split('.')[0]  # Remove microseconds
            else:
                return "Refreshing soon..."
        else:
            # Calculate based on last_refresh from DB
            return "Calculating..."

def init_auto_refresh_tracking():
    """Initialize auto-refresh tracking for all keys"""
    all_keys = get_all_api_keys()
    with auto_refresh_lock:
        for key_data in all_keys:
            api_key = key_data['api_key']
            last_refresh = key_data.get('last_refresh')
            
            if last_refresh:
                try:
                    last_refresh_time = datetime.fromisoformat(last_refresh.replace('Z', '+00:00'))
                    next_refresh = last_refresh_time.replace(tzinfo=None) + timedelta(seconds=AUTO_REFRESH_INTERVAL)
                    auto_refresh_status[api_key] = {
                        'last_refresh': last_refresh_time.replace(tzinfo=None),
                        'next_refresh': next_refresh
                    }
                except:
                    auto_refresh_status[api_key] = {
                        'last_refresh': None,
                        'next_refresh': datetime.now()  # Refresh immediately
                    }
            else:
                auto_refresh_status[api_key] = {
                    'last_refresh': None,
                    'next_refresh': datetime.now()  # Refresh immediately
                }

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_data = get_user_by_username(username)
        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(user_data['id'], username, user_data['password_hash'])
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        existing_user = get_user_by_username(username)
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        user_data = create_user(username, generate_password_hash(password))
        if user_data:
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    username = current_user.username
    keys = get_user_keys(username)
    
    enriched_keys = []
    for api_key, key_data in keys.items():
        uid_count = get_uid_count(api_key)
        token_count = get_token_count(api_key)
        time_left = get_time_until_next_refresh(api_key)
        auto_refresh = key_data.get('auto_refresh', True)
        
        enriched_keys.append({
            'key': api_key,
            'uid_count': uid_count,
            'token_count': token_count,
            'created_at': key_data.get('created_at', 'Unknown'),
            'last_refresh': key_data.get('last_refresh', 'Never'),
            'successful_uids': key_data.get('successful_uids', 0),
            'failed_uids': key_data.get('failed_uids', 0),
            'time_until_refresh': time_left,
            'auto_refresh': auto_refresh
        })
    
    return render_template('dashboard.html', keys=enriched_keys, username=username)

@app.route('/generate-key', methods=['GET', 'POST'])
@login_required
def generate_key():
    if request.method == 'POST':
        api_key = request.form.get('api_key')
        if not api_key:
            api_key = f"key_{uuid.uuid4().hex[:8]}"
        
        if 'uid_file' not in request.files:
            flash('No file uploaded', 'error')
            return render_template('generate_key.html')
        
        file = request.files['uid_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return render_template('generate_key.html')
        
        if file and file.filename.endswith('.json'):
            try:
                uid_data = json.load(file)
                username = current_user.username
                
                key_result = create_api_key(username, api_key, len(uid_data))
                if not key_result:
                    flash('Failed to create API key', 'error')
                    return render_template('generate_key.html')
                
                if not save_uids_batch(api_key, username, uid_data):
                    flash('Failed to save UIDs', 'error')
                    return render_template('generate_key.html')
                
                # Initialize auto-refresh tracking
                with auto_refresh_lock:
                    auto_refresh_status[api_key] = {
                        'last_refresh': None,
                        'next_refresh': datetime.now()  # Refresh immediately on first run
                    }
                
                flash(f'Key "{api_key}" generated successfully with {len(uid_data)} UIDs!', 'success')
                return redirect(url_for('dashboard'))
                
            except json.JSONDecodeError:
                flash('Invalid JSON file', 'error')
            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'error')
        else:
            flash('Please upload a JSON file', 'error')
    
    return render_template('generate_key.html')

@app.route('/refresh-token/<key>')
@login_required
def refresh_token(key):
    username = current_user.username
    
    success, result = refresh_tokens_for_key_fast(key, username)
    
    if success:
        # Success message
        flash(f'⚡ Refresh Complete! {result["tokens_generated"]}/{result["total_uids"]} tokens in {result["time_taken"]}', 'success')
        
        # Show failed UIDs if any
        failed_list = result.get("failed_uid_passwords", [])
        if failed_list:
            failed_msg = f'❌ Failed UIDs ({len(failed_list)}):\n'
            for item in failed_list[:5]:  # Show first 5
                failed_msg += f"UID: {item['uid']} | Pass: {item['password'][:20]}...\n"
            if len(failed_list) > 5:
                failed_msg += f"... and {len(failed_list) - 5} more"
            flash(failed_msg, 'error')
    else:
        flash(f'Failed to refresh tokens: {result}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/toggle-auto-refresh/<key>')
@login_required
def toggle_auto_refresh(key):
    """Toggle auto-refresh for a key"""
    # Get current state
    keys = get_user_keys(current_user.username)
    if key in keys:
        current_state = keys[key].get('auto_refresh', True)
        new_state = not current_state
        set_auto_refresh(key, new_state)
        
        if new_state:
            flash(f'Auto-refresh enabled for key "{key}"', 'success')
        else:
            flash(f'Auto-refresh disabled for key "{key}"', 'warning')
    
    return redirect(url_for('dashboard'))

@app.route('/delete-key/<key>')
@login_required
def delete_key(key):
    if delete_api_key(key):
        flash(f'Key "{key}" deleted successfully!', 'success')
    else:
        flash(f'Failed to delete key "{key}"', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/api-docs')
@login_required
def api_docs():
    return render_template('api_docs.html')

@app.route('/api/auto-refresh-status')
@login_required
def auto_refresh_status_api():
    """API to get auto-refresh status for all keys"""
    username = current_user.username
    keys = get_user_keys(username)
    
    status_list = []
    for api_key, key_data in keys.items():
        time_left = get_time_until_next_refresh(api_key)
        status_list.append({
            'key': api_key,
            'auto_refresh': key_data.get('auto_refresh', True),
            'time_until_refresh': time_left,
            'last_refresh': key_data.get('last_refresh', 'Never')
        })
    
    return jsonify(status_list)

# API Routes
@app.route('/api/likes', methods=['GET'])
def api_likes():
    api_key = request.args.get("key")
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "IND").upper()
    
    if not api_key or not uid:
        return jsonify({"error": "API key and UID are required"}), 400
    
    username = find_user_by_api_key(api_key)
    if not username:
        return jsonify({"error": "Invalid API key"}), 401
    
    tokens = get_active_tokens(api_key)
    
    if not tokens:
        return jsonify({"error": "No active tokens found. Please refresh tokens first."}), 400
    
    total_tokens = len(tokens)
    logger.info(f"Sending likes to UID {uid} using {total_tokens} tokens")
    
    token = tokens[0]
    encrypt = enc(uid)
    
    before = make_request(encrypt, server_name, token)
    if before is None:
        return jsonify({"error": "Failed to fetch user data"}), 500
    
    jsone = MessageToJson(before)
    data = json.loads(jsone)
    before_like = int(data['AccountInfo'].get('Likes', 0))
    
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/LikeProfile"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/LikeProfile"
    else:
        url = "https://clientbp.ggblueshark.com/LikeProfile"
    
    start_time = time.time()
    results = asyncio.run(send_all_likes_batch(uid, server_name, url, tokens))
    elapsed_time = time.time() - start_time
    
    successful_requests = sum(1 for r in results if r.get('success'))
    failed_requests = len(results) - successful_requests
    rate_limited = sum(1 for r in results if r.get('status') == 503)
    
    logger.info(f"Likes completed: {successful_requests}/{total_tokens} successful")
    
    after = make_request(encrypt, server_name, token)
    if after is None:
        return jsonify({
            "error": "Failed to fetch updated user data",
            "tokens_used": total_tokens,
            "successful_requests": successful_requests,
            "failed_requests": failed_requests
        }), 500
    
    jsone = MessageToJson(after)
    data = json.loads(jsone)
    after_like = int(data['AccountInfo']['Likes'])
    player_name = data['AccountInfo'].get('PlayerNickname', 'Unknown')
    player_uid = int(data['AccountInfo'].get('UID', uid))
    like_given = after_like - before_like
    
    return jsonify({
        "LikesGivenByAPI": like_given,
        "LikesafterCommand": after_like,
        "LikesbeforeCommand": before_like,
        "PlayerNickname": player_name,
        "UID": player_uid,
        "status": 1 if like_given > 0 else 2
    })

@app.route('/api/refresh/<key>', methods=['GET'])
def api_refresh_tokens(key):
    username = find_user_by_api_key(key)
    if not username:
        return jsonify({"error": "Invalid API key"}), 401
    
    success, result = refresh_tokens_for_key_fast(key, username)
    
    if not success:
        return jsonify({"error": result}), 404
    
    return jsonify({
        "status": "success",
        "key": key,
        "result": result
    })

if __name__ == '__main__':
    # Initialize Supabase
    try:
        supabase = create_supabase_client()
        logger.info("Supabase connected successfully")
        
        # Initialize auto-refresh tracking
        init_auto_refresh_tracking()
    except Exception as e:
        logger.error(f"Failed to connect to Supabase: {e}")
    
    # Setup scheduler for auto-refresh every hour (check if 6 hours passed)
    schedule.every(1).hours.do(auto_refresh_all_keys)
    
    # Run initial check
    logger.info("Running initial auto-refresh check...")
    auto_refresh_all_keys()
    
    # Start scheduler in background thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    logger.info("Auto-refresh scheduler started (checks every hour, refreshes every 6 hours)")
    
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)
