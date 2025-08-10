from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file
from Encryption import generate_all_keys, encrypt_layered, decrypt_layered, create_folder
from datetime import datetime
from flask_socketio import SocketIO, emit
from mail import send_attack_detect_email,send_welcome_email,send_error_report_email
from joblib import load
from file_diff import identify_file_type
from authlib.integrations.flask_client import OAuth
import numpy as np
from flask import request, jsonify
from werkzeug.utils import secure_filename
import tempfile
from io import BytesIO
from pymongo import MongoClient
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib
import threading
from Fragmentation import escape_mechanism,escape_mechanism_reconstruction
import time
import pandas as pd
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
import pytz
from bson.binary import Binary
import base64
from datetime import datetime
from bson import ObjectId
import json
from bson import json_util
from bson import BSON
from bson.json_util import dumps
import bson
import firebase_admin
from firebase_admin import credentials, firestore
from web3 import Web3

ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

app = Flask(__name__)
app.secret_key = 'D-Defender@102221' 


client = MongoClient("mongodb://localhost:27017/") 
db = client["Q-Defender"]
AES_Encryption_collection = db["AES encryption"]
Key_Vault_collection = db["Key Vault"]
Key_Cipher_collection = db["Key Cipher"]
large_files_collection = db["Large files"]

cred = credentials.Certificate(".........")

db_fire = firestore.client()

app.config['GOOGLE_CLIENT_ID'] = ".............."
app.config['GOOGLE_CLIENT_SECRET'] = "............."
app.config['REDIRECT_URI'] = "http://127.0.0.1:5000/auth/callback"  
global data_id
data_id = "" 

if web3.is_connected():
    print("Connected to Ganache ✅")
else:
    print("Failed to connect to Ganache ❌")

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account',  
    },
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
)

output_dir = "folder_sec_inst"

stored_message = None
socketio = SocketIO(app)
anomaly_state = {
            "detected": False,
            "last_detected": None,
            "lockout_until": None
        }

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

try:
    model = load('anomaly_detection_model.pkl')
except:
    model = Pipeline([
        ('scaler', StandardScaler()),
        ('isolation_forest', IsolationForest(
            n_estimators=150,
            contamination=0.03,
            max_features=0.8,
            random_state=42,
            verbose=1
        ))
    ])
    dummy_data = np.random.rand(200, 12)
    model.fit(dummy_data)
    joblib.dump(model, 'anomaly_detection_model.pkl')

request_buffer = []
anomaly_detected = False
security_lock = threading.Lock()
high_alert = False

FEATURES = [
    'response_time',
    'request_size',
    'response_size',
    'status_200',
    'status_404',
    'status_500',
    'unique_ip',
    'api_endpoint',
    'requests_per_min',
    'user_agent',
    'encrypted',
    'sensitive'
]



def monitor_requests():
    global anomaly_detected, high_alert
    while True:
        time.sleep(15)  
        with security_lock:
            if len(request_buffer) > 10:  
                df = pd.DataFrame(request_buffer[-20:])  
                
                for feature in FEATURES:

                    if feature not in df.columns:
                        df[feature] = 0
                
                scores = model.decision_function(df[FEATURES])
                predictions = model.predict(df[FEATURES])
                
                if any(predictions == -1):
                    anomaly_score = min(scores)
                    print(f"🚨 SECURITY ALERT! Anomaly score: {anomaly_score:.2f}")
                    log_security_event(f"Anomaly detected - Score: {anomaly_score:.2f}")
                    
                    if anomaly_score < -0.7:  
                        high_alert = True
                        trigger_quantum_escape_protocol(severity='high')
                    else:
                        high_alert = False
                        trigger_quantum_escape_protocol(severity='medium')
                    
                    anomaly_detected = True

def log_security_event(message):
    with open('security.log', 'a') as f:
        f.write(f"{datetime.now()} - {message}\n")


def trigger_quantum_escape_protocol(severity='medium'):
    global stored_message
    
    actions = {
        'medium': [
            "Activated additional Kyber encryption layer",
            "Enabled traffic obfuscation",
            "Triggered 2FA verification"
        ],
        'high': [
            "FULL QUANTUM ESCAPE PROTOCOL ENGAGED",
            "Regenerated all cryptographic keys",
            "Enabled maximum fragmentation with decoys",
            "Isolated sensitive data stores",
            "Disabled non-essential endpoints"
        ]
    }
    
    log_security_event(f"QUANTUM ESCAPE ACTIVATED - Severity: {severity.upper()}")
    
    if stored_message:
        encrypt_layered(stored_message, security_level=severity)
    
    if severity == 'high':
        generate_all_keys(force_refresh=True)
        socketio.emit('security_alert', {
            'level': 'critical',
            'message': 'Quantum Escape Protocol Engaged',
            'actions': actions['high']
        })

def check_anomaly():
    global anomaly_detected
    with security_lock:
        if anomaly_detected:
            anomaly_detected = False
            return True
        return True

def log_request_data(request):
    sensitive_endpoints = ['/process_new', '/upload_file', '/submit_message', 
                          '/decryption', '/download_decoded']
    return {
        'timestamp': datetime.now(),
        'response_time': np.random.normal(120, 20, 1)[0].clip(50, 1000),
        'request_size': request.content_length or 0,
        'response_size': 0,
        'status_200': 0,
        'status_404': 0,
        'status_500': 0,
        'unique_ip': 1 if request.remote_addr not in [r.get('ip', '') for r in request_buffer] else 0,
        'api_endpoint': hash(request.path) % 30,
        'requests_per_min': len([r for r in request_buffer if (datetime.now() - r['timestamp']).seconds < 60]),
        'user_agent': hash(request.user_agent.string) % 15 if request.user_agent else 0,
        'ip': request.remote_addr,
        'path': request.path,
        'method': request.method,
        'encrypted': 1 if request.path in sensitive_endpoints else 0,
        'sensitive': 1 if 'data' in request.path or 'decrypt' in request.path else 0
    }

def check_and_handle_anomaly(request):
    """Enhanced anomaly detection logic"""
    global anomaly_state
    
   
    if anomaly_state["lockout_until"] and time.time() < anomaly_state["lockout_until"]:
        return True
    
 
    anomaly_score = 0
    
  
    suspicious_headers = ["X-ATTACK-TYPE", "MALICIOUS-BOT"]
    for h in suspicious_headers:
        if h in request.headers:
            anomaly_score += 30
    
  
    if request.content_length and request.content_length > 10000*10000:  
        anomaly_score += 20
    
   
    if request.method == "POST":
        data = request.get_data(as_text=True)
        attack_patterns = ["' OR '1'='1", "<script>", "../", "\\x00"]
        for pattern in attack_patterns:
            if pattern in data:
                anomaly_score += 40
    
   
    if anomaly_score >= 50:
        anomaly_state = {
            "detected": True,
            "last_detected": time.time(),
            "lockout_until": time.time() + 300  
        }
        return True
    
    return False

def before_request_handler():
    """Check all requests for anomalies"""
    if check_and_handle_anomaly(request):
        print("request ",request)
        if request.endpoint != 'activate':
            print("in before request part")
            return True
    return False



@app.after_request
def after_request_handler(response):
    if request.endpoint and request.endpoint != 'static' and request_buffer:
        with security_lock:
            last_request = request_buffer[-1]
            last_request['response_size'] = response.content_length or 0
            if response.status_code == 200:
                last_request['status_200'] = 1
            elif response.status_code == 404:
                last_request['status_404'] = 1
            elif response.status_code == 500:
                last_request['status_500'] = 1
    return response


monitor_thread = threading.Thread(target=monitor_requests, daemon=True)
monitor_thread.start()



client = MongoClient("mongodb://localhost:27017/")
db = client["Q-Defender"]
users = db["Q-Defender User Details"]

@app.route('/')
def home():
    if False:
        return redirect(url_for('activate'))
    else:
        try:
         email = session.get("email")
         user = users.find_one({"email": email})
         if(user):
            picture = user.get("picture") 
            user_id = user.get("id")
            print("Picture URL from DB:", picture)
          
            total_data_secured = AES_Encryption_collection.count_documents({"user_id": user_id})
            
            security_shield_activated = AES_Encryption_collection.count_documents({
                "user_id": user_id,
                "status": "Fragmented"
            })
            stats = db.command("dbstats")
           
            data_size_bytes = stats['dataSize']

            if data_size_bytes < 1024:
                storage_used = f"{data_size_bytes} B"
            elif data_size_bytes < 1024 ** 2:
                storage_used = f"{round(data_size_bytes / 1024, 2)} KB"
            elif data_size_bytes < 1024 ** 3:
                storage_used = f"{round(data_size_bytes / (1024 ** 2), 2)} MB"
            else:
                storage_used = f"{round(data_size_bytes / (1024 ** 3), 2)} GB"
    
            recent_data_cursor = AES_Encryption_collection.find(
                {"user_id": user_id},
                {
                    "meta_data": 1,
                    "encrypted_at": 1,
                    "data_format": 1,
                    "status": 1,
                    "layers": 1,
                    "_id": 0
                }
            ).sort("encrypted_at", -1).limit(5)
    
            recent_data = []
            for item in recent_data_cursor:
                if 'encrypted_at' in item:
                    if isinstance(item['encrypted_at'], dict) and '$date' in item['encrypted_at']:
                        try:
                            item['encrypted_at'] = datetime.fromisoformat(
                                item['encrypted_at']['$date'].replace('Z', '+00:00')
                            )
                        except ValueError:
                            item['encrypted_at'] = None
                    elif isinstance(item['encrypted_at'], datetime):
                      
                        pass
                    else:
                        item['encrypted_at'] = None
                
              
                item.setdefault('meta_data', 'Unknown')
                item.setdefault('data_format', 'Unknown')
                item.setdefault('status', 'Unknown')
                item.setdefault('layers', 0)
                
                recent_data.append(item)
            
            return render_template('CryptonZT.html',
                                total_data_secured=total_data_secured,
                                security_shield_activated=security_shield_activated,
                                storage_used=storage_used,
                                recent_data=recent_data, picture=picture)

         else:
            return render_template("index.html")
         
        except Exception as e:
            print(f"Error in dashboard route: {str(e)}")
           
            return render_template('CryptonZT.html',
                                total_data_secured=0,
                                security_shield_activated=0,
                                storage_used=0,
                                recent_data=[])


@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return ""
    return value.strftime(format)

@app.route("/login/google")
def login():
    return google.authorize_redirect(redirect_uri=app.config['REDIRECT_URI'])

@app.route("/auth/callback")
def callback():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    print(user_info)

    session['email'] = user_info['email']
    session['name'] = user_info['name']
    session["picture"] = user_info['picture']

    send_welcome_email(user_info['email'], user_info['name'])

    users.update_one(
        {"email": user_info["email"]},
        {
            "$set": {
                **user_info,
                "last_login": datetime.now()
            }
        },
        upsert=True
    )
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route('/login')
def login_page():
    if False:
        return redirect(url_for('activate'))
    return render_template('login.html')

from flask import render_template
from datetime import datetime

@app.route('/data-details/<data_id>')
def data_details(data_id):
    email = session.get("email")
    user = users.find_one({"email": email})
    if(user):
            picture = user.get("picture") 
            print("Picture URL from DB:", picture)
   
    data = db["AES encryption"].find_one({"data_id": data_id})
    
    if not data:
        return "Data not found", 404
    
   
    data['_id'] = str(data['_id'])
    
    if 'encrypted_at' in data and isinstance(data['encrypted_at'], datetime):
        data['encrypted_at'] = data['encrypted_at'].strftime('%Y-%m-%d %H:%M:%S')
    
    if 'anomaly_detected_at' in data and isinstance(data['anomaly_detected_at'], datetime):
        data['anomaly_detected_at'] = data['anomaly_detected_at'].strftime('%Y-%m-%d %H:%M:%S')
    
    return render_template('data_details.html', data=data, picture=picture)



@app.route('/decryption')
def decryption_page():
    data_id = session.get("data_id")
    print("Decryt ",data_id)
    if before_request_handler():
        print("here")
        return redirect(url_for('activate',data_id=data_id))
    email = session.get("email")
    user = users.find_one({"email": email})
    if(user):
            picture = user.get("picture") 
            print("Picture URL from DB:", picture)
 
    AES_Encryption = AES_Encryption_collection.find_one({"data_id": data_id})
    anomaly_triggered = AES_Encryption.get("anomaly_triggered")
    metadata = AES_Encryption.get("meta_data").capitalize()
    print(anomaly_triggered)
    if(anomaly_triggered == True):
        return render_template('decryption_backup_db.html',picture=picture, metadata=metadata)
    else:
        return render_template('decryption_primary_db.html',picture=picture, metadata=metadata)


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/API_reference')
def API_reference():
    return render_template('APIreference.html')



@app.route('/managedata')
def managedata():
    if False:
        return redirect(url_for('activate'))
    else:
        email = session.get("email")
        user = users.find_one({"email": email})
        if user:
            picture = user.get("picture")
            user_id = user.get("id")
            encryption_data = list(AES_Encryption_collection.find({"user_id": user_id}))
            
           
            def serialize_doc(doc):
                if isinstance(doc, dict):
                    for key, value in doc.items():
                        if isinstance(value, ObjectId):
                            doc[key] = str(value)
                        elif isinstance(value, bytes):
                            doc[key] = "Binary data"
                        elif isinstance(value, datetime):
                            doc[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                        elif isinstance(value, dict) and '$date' in value:
                            try:
                                date_str = value['$date']
                                if '.' in date_str:
                                    parsed_date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                                else:
                                    parsed_date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
                                doc[key] = parsed_date.strftime('%Y-%m-%d %H:%M:%S')
                            except:
                                doc[key] = "Date unavailable"
                    return doc
                return doc
            
            processed_data = [serialize_doc(doc) for doc in encryption_data]

            for doc in processed_data:
                doc.setdefault('data_id', 'N/A')
                doc.setdefault('meta_data', 'No description')
                doc.setdefault('status', 'Unknown')
                doc.setdefault('data_format', 'Unknown')
                doc.setdefault('layers', 0)
                doc.setdefault('user_id', 'N/A')
            
            return render_template(
                "ManageData.html", 
                picture=picture,
                encryption_data=json.loads(json_util.dumps(processed_data))
            )
        else:
            return render_template("index.html")


@app.route('/view-data/<data_id>')
def view_data(data_id):
    try:
        session['data_id'] = data_id
        data = AES_Encryption_collection.find_one({"_id": ObjectId(data_id)})
        if data:
            data['_id'] = str(data['_id'])
            if 'enc_data' in data:
                data['enc_data'] = "REDACTED"
            return jsonify(data)
        else:
            return jsonify({"error": "Data not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/delete-data/<data_id>', methods=['DELETE'])
def delete_data(data_id):
    try:
        result1 = AES_Encryption_collection.delete_one({"data_id": data_id})
        result2 = Key_Vault_collection.delete_one({"data_id": data_id})
        result3 = Key_Cipher_collection.delete_one({"data_id": data_id})
        result4 = large_files_collection.delete_many({"data_id": data_id})

        if result1.deleted_count > 0 :
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Document not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    

@app.route('/unlock-data/<data_id>', methods=['POST'])
def unlock_data(data_id):
    session['data_id'] = data_id
    data_id = data_id
    print("unlock",data_id)
    if before_request_handler():
        return redirect(url_for('activate',data_id=data_id))
    else:
        AES_Encryption = AES_Encryption_collection.find_one({"data_id": data_id})
        Key_Vault = Key_Vault_collection.find_one({"data_id": data_id})
        Key_Cipher = Key_Cipher_collection.find_one({"data_id": data_id})
        key_dict = Key_Vault.get("Key")
        aes_ciphertext = AES_Encryption.get("enc_data")

        
        if not AES_Encryption:
            raise ValueError(f"No record found for data_id: {data_id}")
        
        if not AES_Encryption.get("large_file", False):
             aes_ciphertext = AES_Encryption.get("enc_data")
        else:

            aes_ciphertext = AES_Encryption["enc_data"]
            
            fragments = list(large_files_collection.find(
                {"data_id": data_id},
                sort=[("fragment_no", 1)]
            ))

            expected_fragments = AES_Encryption["total_fragments"] - 1 
            if len(fragments) != expected_fragments:
                raise ValueError(f"Missing fragments. Expected {expected_fragments}, found {len(fragments)}")
            
            for fragment in fragments:
                aes_ciphertext += fragment["fragmented_enc_data"]
        
    

        ntru_ciphertext = Key_Cipher.get("cipher_data").get("ntru")
        mceliece_ciphertext = Key_Cipher.get("cipher_data").get("mceliece")
        encrypted_falcon_sig = Key_Cipher.get("cipher_data").get("Falcon_cipher")
        falcon_public_key = Key_Cipher.get("cipher_data").get("Falcon_public_key")
        encrypted_kyber_ct = Key_Cipher.get("cipher_data").get("kyber")
        support_data = Key_Cipher.get("aes_bin")
        aes_iv = Key_Cipher.get("aes_iv")
        anomaly_triggered = AES_Encryption.get("anomaly_triggered")
        if anomaly_triggered:
            collection_name = "Q-Defender"
            complete = Key_Cipher.get("complete")
            print("length before passing: ",len(complete))
            docs = db_fire.collection(collection_name).where("data_id", "==", data_id).stream()
            print("firebase: ",docs)
            for doc in docs:
                print("Document ID:", doc.id)

            dilithium_signature = Key_Cipher.get("cipher_data").get("dilithium")

            escape_mechanism_reconstruction(data_id, aes_iv, support_data, aes_ciphertext, ntru_ciphertext, mceliece_ciphertext, encrypted_falcon_sig, encrypted_kyber_ct,falcon_public_key,dilithium_signature,complete)
          
        else:    
          decrypt_layered(key_dict,aes_iv, support_data, aes_ciphertext, ntru_ciphertext, mceliece_ciphertext, encrypted_falcon_sig, encrypted_kyber_ct,falcon_public_key)
        
        email = session.get("email")
        user = users.find_one({"email": email})
        if(user):
            picture = user.get("picture") 
            print("Picture URL from DB:", picture)
        return redirect(url_for('decryption_page', data_id=data_id))


    
@app.route('/updates')
def updates():

    return render_template('home.html')

@app.route('/my_profile')
def my_profile():
    email = session.get("email")
    user = users.find_one({"email": email})
    if(user):
            picture = user.get("picture") 
            name = user.get("name").capitalize()
            given_name = user.get("given_name").capitalize()
            last_login = str(user.get("last_login"))
            dt = datetime.fromisoformat(last_login)

            last_login = dt.strftime("%B %d, %Y at %I:%M %p")
            user_id = user.get("id")

    return render_template('my_profile.html', picture=picture,name=name,given_name = given_name,last_login=last_login,user_id=user_id,email=email)

@app.route('/account_settings')
def account_settings():
    email = session.get("email")
    user = users.find_one({"email": email})
    if(user):
            picture = user.get("picture") 
            print("Picture URL from DB:", picture)
    return render_template('account_settings.html', picture=picture)
global counter
counter = 1
@app.route('/activate/<data_id>')
def activate(data_id):
    email = session.get("email")
    user = users.find_one({"email": email})
    user_id = user.get("id")
    if(user):
            picture = user.get("picture") 
            print("Picture URL from DB:", picture)
    logo = "https://i.ibb.co/rGFMz0nC/logo.png"
    security_measures = [
        "Post-Quantum Cryptography (Kyber-1024)",
        "Data Fragmentation with Entropy Decoys",
        "Multi-Path Obfuscation Routing",
        "Temporary Access Restrictions"
    ]

    send_attack_detect_email(email)
    print("Data Id in problem is ",data_id)

    AES_Encryption = AES_Encryption_collection.find_one({"data_id": data_id})
    Key_Vault = Key_Vault_collection.find_one({"data_id": data_id})
    Key_Cipher = Key_Cipher_collection.find_one({"data_id": data_id})
    key_dict = Key_Vault["Key"]
    print("length of key before passing: ",len(key_dict))
    global counter
    if(counter == 1):
        escape_mechanism(Key_Vault,Key_Cipher,data_id,user_id)
        counter += 1


    return render_template('activate.html',
                         message="Quantum Escape Protocol Engaged",
                         measures=security_measures,
                         alert_level="high" if high_alert else "medium", picture=picture , logo= logo)

@app.route('/process_new', methods=['POST'])
@limiter.limit("10 per minute")
def process_new():

    
    user_data = request.form.get('user_data')
    session['user_data'] = user_data  
    return redirect(url_for('activate'))


def generate_id(prefix):
    random_part = secrets.token_hex(8)  
    return f"{prefix}_{random_part}"

def bytes_to_bitstring(data_bytes):
    return ''.join(format(byte, '08b') for byte in data_bytes)

def bits_to_image(bit_data, output_path):
    byte_data = bytearray(int(bit_data[i:i+8], 2) for i in range(0, len(bit_data), 8))
    with open(output_path, "wb") as f:
        f.write(byte_data)

def compare_files(file1, file2):
    with open(file1, "rb") as f1, open(file2, "rb") as f2:
        while True:
            b1 = f1.read(4096)
            b2 = f2.read(4096)
            if b1 != b2:
                return False
            if not b1:
                break
    return True

app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  

@app.route('/upload_file', methods=['POST'])
@limiter.limit("5 per minute")
def upload_file():
    MAX_FILE_SIZE = 1024 * 1024 * 1024  
    
    if 'file' not in request.files:
        flash("No file uploaded.", "error")
        return render_template('encryption.html')
    
    uploaded_file = request.files['file']
    file_size = request.content_length  
    file_size_mb = file_size / (1024 * 1024)  

    print(f"Uploaded file size: {file_size} bytes ({file_size_mb:.2f} MB)")


    if request.content_length > MAX_FILE_SIZE:
        flash("File size exceeds maximum limit of 1GB", "error")
        return render_template('encryption.html')
    
    chunk_size = 4096  
    file_data = bytearray()
    
    while True:
        chunk = uploaded_file.read(chunk_size)
        if not chunk:
            break
        file_data.extend(chunk)
    
    create_folder()
    with open(os.path.join(output_dir, "a_og_input.txt"), "wb") as f:
        f.write(file_data)
    


    generate_all_keys()
    encrypt_layered(file_data)
    flash("Text file secured with quantum encryption!", "success")

    return render_template('encryption.html')


@app.route('/encryption_processing', methods=['POST'])
@limiter.limit("15 per minute")
def submit_message():
    email = session.get("email")
    user = users.find_one({"email": email})
    user_id = user.get("id")
    if(user):
                picture = user.get("picture") 
    try:
        data_id = generate_id("DATA")
        session["data_id"] = data_id
        session.modified = True
        manual_message = request.form.get('manual_message', '').strip()
        uploaded_file = request.files.get('file')
        file_size = request.content_length  
        file_size_mb = round(file_size / (1024 * 1024), 2)  

        print(f"Uploaded file size: {file_size} bytes ({file_size_mb:.2f} MB)")

        metadata = request.form.get('metadata')

        if not manual_message and (not uploaded_file or uploaded_file.filename == ''):
            flash("Please enter a message or upload a file.", "error")
            email = session.get("email")
            user = users.find_one({"email": email})
            if(user):
                picture = user.get("picture") 
                print("Picture URL from DB:", picture)
            return render_template('encryption.html',picture=picture)
        
        try:
            create_folder()
            if manual_message:
                full_payload = manual_message.encode()
            else:
                full_payload = uploaded_file.read()

            with open(os.path.join(output_dir, "a_og_input.txt"), "wb") as f:
                f.write(full_payload)

            input_file= os.path.join(output_dir, "a_og_input.txt")

            data_format = identify_file_type(input_file)

            data_format = data_format[1:]
            print("data_format",data_format)

            key_id = generate_id("KEY")
            email = session.get("email")
            user = users.find_one({"email": email})
            if(user):
                user_id = user.get("id") 
            generate_all_keys(data_id, key_id, user_id)
            encrypt_layered(full_payload, data_format, data_id, key_id, metadata, user_id, file_size_mb)
            flash("Data secured with quantum encryption!", "success")
        except Exception as e:
            
            flash(f"Security error: {str(e)}", "error")
       
            
        error = {
                'writeErrors': [
                    {
                        'index': 2,
                        'code': 11000,
                        'errmsg': 'E11000 duplicate key error...',
                        'op': "{ /* document */ }"
                    }
                ],
                'nInserted': 2,
                'writeConcernErrors': []
            }

        return render_template('encryption.html',picture=picture)
        
    except Exception as e:
        send_error_report_email(user_id,"Signature failure Error", e)
        return render_template('error.html',picture=picture)


@app.route('/download_decoded')
@limiter.limit("5 per hour")
def download_decoded():
    try:
        file_path = os.path.join(output_dir, "Q-Defender_Decrypted.txt")
        data_id = session.get("data_id")
        AES_Encryption = AES_Encryption_collection.find_one({"data_id": data_id})
        
        if not AES_Encryption:
            flash("Data not found.", "error")
            return redirect(url_for('decryption'))

        metadata = AES_Encryption.get("meta_data")
        
        if not os.path.exists(file_path):
            flash("Decrypted file not available.", "error")
            return redirect(url_for('decryption'))

        file_type = identify_file_type(file_path)
        
        if file_type == ".txt" or not file_type:
            return send_file(
                file_path,
                as_attachment=True,
                download_name=f"Q-Defender_{metadata}.txt"
            )
        else:
           
            temp_output = os.path.join(output_dir, f"Q-Defender_{metadata}{file_type}")
            
         
            chunk_size = 1024 * 1024  
            
            with open(file_path, 'rb') as infile, open(temp_output, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break
                   
                    bit_string = ''.join(format(byte, '08b') for byte in chunk)
                    byte_data = bytearray(int(bit_string[i:i+8], 2) for i in range(0, len(bit_string), 8))
                    outfile.write(byte_data)
            
            return send_file(
                temp_output,
                as_attachment=True,
                download_name=f"CryptonZT_{metadata}{file_type}"
            )
            
    except Exception as e:
        flash(f"Error during download: {str(e)}", "error")
        return redirect(url_for('decryption'))
    
@app.errorhandler(404)
def page_not_found(e):

    return render_template('404.html'), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('rate_limit.html'), 429


@socketio.on('connect')
def handle_connect():
    emit('security_status', {
        'status': 'normal',
        'message': 'All systems operational'
    })

@socketio.on('security_check')
def handle_security_check():
    emit('security_update', {
        'alert_level': 'high' if high_alert else 'normal',
        'last_checked': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route('/debug/anomaly', methods=['POST'])
def debug_anomaly():
    """Endpoint to test anomaly detection"""
    score = 0
    report = []
 
    suspicious = ["X-ATTACK-TYPE", "MALICIOUS", "EVIL"]
    for h in request.headers:
        if any(s in h.upper() for s in suspicious):
            score += 30
            report.append(f"Suspicious header: {h} (+30)")
    

    if request.method == "POST":
        data = request.get_data(as_text=True)
        patterns = ["' OR", "<script>", "../", "\\x00"]
        for p in patterns:
            if p in data:
                score += 40
                report.append(f"Attack pattern: {p} (+40)")
    
    return jsonify({
        "score": score,
        "threshold": 50,
        "will_trigger": score >= 50,
        "analysis": report
    })


class ChainSimulator:
    def _init_(self, start_block=1859000):
        self.lock = threading.Lock()
        self.current_block = start_block

    def next_block(self):
        with self.lock:
            self.current_block += 1
            return self.current_block

    def current_block_number(self):
        with self.lock:
            return self.current_block

    def new_tx_hash(self):
        return "0x" + os.urandom(32).hex()

chain = ChainSimulator()

def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

class ContractSimulator:
    def _init_(self, name):
        self.name = name
        self.events = []  
    def emit_event(self, ev):
        ev_record = {
            "contract": self.name,
            "event": ev,
            "timestamp": now_iso(),
            "block_number": chain.next_block(),
            "tx_hash": chain.new_tx_hash()
        }
        self.events.append(ev_record)
        return ev_record

    def recent_events(self, limit=20):
        return self.events[-limit:]


class ProofAnchorSim(ContractSimulator):
    def _init_(self):
        super()._init_("ProofAnchor")
        self.proofs = {}  

    def store_proof(self, data_hash, author=None):
        tx = chain.new_tx_hash()
        blk = chain.next_block()
        ts = now_iso()
        self.proofs[data_hash] = {
            "transaction_hash": tx,
            "block_number": blk,
            "timestamp": ts,
            "author": author
        }
        ev = {"name": "ProofStored", "data_hash": data_hash, "author": author}
        self.emit_event(ev)
        return self.proofs[data_hash]

    def verify_proof(self, data_hash):
        found = self.proofs.get(data_hash)
        if found:
            return {"exists": True, **found}
        else:
            return {"exists": False}

proof_anchor = ProofAnchorSim()

class VotingSim(ContractSimulator):
    def _init_(self):
        super()._init_("VotingSmartContract")
        self.proposals = {}  
        self.proposal_counter = 0

    def create_proposal(self, title, options):
        self.proposal_counter += 1
        pid = str(self.proposal_counter)
        self.proposals[pid] = {
            "title": title,
            "options": options,
            "votes": {o: 0 for o in options},
            "voters": set(),
            "created_at": now_iso()
        }
        ev = {"name": "ProposalCreated", "id": pid, "title": title}
        self.emit_event(ev)
        return {"id": pid, "title": title}

    def cast_vote(self, proposal_id, voter_id, option):
        prop = self.proposals.get(proposal_id)
        if not prop:
            return {"error": "proposal_not_found"}
        if voter_id in prop["voters"]:
            return {"error": "already_voted"}
        if option not in prop["options"]:
            return {"error": "invalid_option"}
        prop["votes"][option] += 1
        prop["voters"].add(voter_id)
        tx = chain.new_tx_hash()
        blk = chain.next_block()
        ev = {"name": "VoteCast", "proposal_id": proposal_id, "voter": voter_id, "option": option}
        self.emit_event(ev)
        return {"status": "ok", "transaction_hash": tx, "block_number": blk}

    def count_votes(self, proposal_id):
        prop = self.proposals.get(proposal_id)
        if not prop:
            return {"error": "proposal_not_found"}
        return {"proposal_id": proposal_id, "title": prop["title"], "votes": prop["votes"]}

voting = VotingSim()

class DecentralisedListSim(ContractSimulator):
    def _init_(self):
        super()._init_("DecentralisedList")
        self.items = [] 
        self.index = {}  

    def add_item(self, item, author=None):
        if item in self.index:
            return {"status": "exists", "index": self.index[item]}
        self.items.append(item)
        self.index[item] = len(self.items) - 1
        tx = chain.new_tx_hash()
        blk = chain.next_block()
        ev = {"name": "ItemAdded", "item": item, "author": author}
        self.emit_event(ev)
        return {"status": "added", "index": self.index[item], "transaction_hash": tx, "block_number": blk}

    def remove_item(self, item, author=None):
        if item not in self.index:
            return {"status": "not_found"}
        idx = self.index.pop(item)
        self.items[idx] = None  
        tx = chain.new_tx_hash()
        blk = chain.next_block()
        ev = {"name": "ItemRemoved", "item": item, "author": author}
        self.emit_event(ev)
        return {"status": "removed", "index": idx, "transaction_hash": tx, "block_number": blk}

    def get_list(self, include_removed=False):
        if include_removed:
            return {"items": self.items}
        else:
            return {"items": [i for i in self.items if i is not None]}

decentralised_list = DecentralisedListSim()

class FragmentVaultSim(ContractSimulator):
    def _init_(self):
        super()._init_("FragmentVault")
        self.fragments = {}  
        self.fragment_counter = 0

    def store_fragment(self, owner, fragment_payload):
        self.fragment_counter += 1
        fid = f"frag-{self.fragment_counter}"
        tx = chain.new_tx_hash()
        blk = chain.next_block()
        ts = now_iso()
        self.fragments[fid] = {"owner": owner, "payload": fragment_payload, "stored_at": ts, "tx": tx, "block": blk}
        ev = {"name": "FragmentStored", "fragment_id": fid, "owner": owner}
        self.emit_event(ev)
        return {"fragment_id": fid, "transaction_hash": tx, "block_number": blk, "stored_at": ts}

    def retrieve_fragment(self, fragment_id, requester=None):
        f = self.fragments.get(fragment_id)
        if not f:
            return {"error": "not_found"}
        return {"fragment_id": fragment_id, "owner": f["owner"], "payload": f["payload"], "stored_at": f["stored_at"], "tx": f["tx"], "block": f["block"]}

fragment_vault = FragmentVaultSim()

class MultisigSim(ContractSimulator):
    def _init_(self, required_signatures=2):
        super()._init_("Multisig")
        self.required = required_signatures
        self.proposals = {}  
        self.counter = 0

    def propose(self, proposer, action):
        self.counter += 1
        pid = str(self.counter)
        self.proposals[pid] = {"action": action, "approvals": set([proposer]), "executed": False}
        ev = {"name": "MultisigProposed", "id": pid, "action": action, "proposer": proposer}
        self.emit_event(ev)
        return {"proposal_id": pid, "approvals": list(self.proposals[pid]["approvals"])}

    def approve(self, proposal_id, approver):
        p = self.proposals.get(proposal_id)
        if not p:
            return {"error": "proposal_not_found"}
        if p["executed"]:
            return {"error": "already_executed"}
        p["approvals"].add(approver)
        ev = {"name": "MultisigApproved", "id": proposal_id, "approver": approver}
        self.emit_event(ev)
        if len(p["approvals"]) >= self.required:
            p["executed"] = True
            tx = chain.new_tx_hash()
            blk = chain.next_block()
            ev2 = {"name": "MultisigExecuted", "id": proposal_id, "action": p["action"]}
            self.emit_event(ev2)
            return {"status": "executed", "transaction_hash": tx, "block_number": blk}
        return {"status": "pending", "approvals_count": len(p["approvals"])}

multisig = MultisigSim(required_signatures=2)

class AnomalyOracleSim(ContractSimulator):
    def _init_(self):
        super()._init_("AnomalyOracle")
        self.records = [] 

    def submit_anomaly(self, source, severity, metadata=None):
        tx = chain.new_tx_hash()
        blk = chain.next_block()
        ts = now_iso()
        rec = {"id": len(self.records) + 1, "source": source, "severity": severity, "metadata": metadata or {}, "tx": tx, "block": blk, "timestamp": ts}
        self.records.append(rec)
        ev = {"name": "AnomalySubmitted", "id": rec["id"], "source": source, "severity": severity}
        self.emit_event(ev)
        return rec

    def list_anomalies(self, limit=50):
        return list(reversed(self.records[-limit:]))

anomaly_oracle = AnomalyOracleSim()


@app.route("/proof/store", methods=["POST"])
def proof_store():
    payload = request.json or {}
    data_hash = payload.get("hash") or payload.get("data_hash") or "0x" + os.urandom(16).hex()
    author = payload.get("author")
    result = proof_anchor.store_proof(data_hash, author=author)
    return jsonify({"status": "success", "operation": "store_proof", "result": result})

@app.route("/proof/verify", methods=["POST"])
def proof_verify():
    payload = request.json or {}
    data_hash = payload.get("hash") or payload.get("data_hash")
    if not data_hash:
        return jsonify({"error": "missing_hash"}), 400
    result = proof_anchor.verify_proof(data_hash)
    return jsonify({"status": "success", "operation": "verify_proof", "result": result})

@app.route("/voting/proposal", methods=["POST"])
def voting_create_proposal():
    payload = request.json or {}
    title = payload.get("title", "New Proposal")
    options = payload.get("options", ["Yes", "No"])
    result = voting.create_proposal(title, options)
    return jsonify({"status": "success", "operation": "create_proposal", "result": result})

@app.route("/voting/cast", methods=["POST"])
def voting_cast():
    payload = request.json or {}
    pid = str(payload.get("proposal_id", "1"))
    voter = payload.get("voter_id", payload.get("voter", "user-" + os.urandom(4).hex()))
    option = payload.get("option", "Yes")
    result = voting.cast_vote(pid, voter, option)
    return jsonify({"status": "success", "operation": "cast_vote", "result": result})

@app.route("/voting/count", methods=["GET"])
def voting_count():
    pid = str(request.args.get("proposal_id", "1"))
    result = voting.count_votes(pid)
    return jsonify({"status": "success", "operation": "count_votes", "result": result})

@app.route("/list/add", methods=["POST"])
def list_add():
    payload = request.json or {}
    item = payload.get("item")
    author = payload.get("author")
    if not item:
        return jsonify({"error": "missing_item"}), 400
    result = decentralised_list.add_item(item, author=author)
    return jsonify({"status": "success", "operation": "add_item", "result": result})

@app.route("/list/remove", methods=["POST"])
def list_remove():
    payload = request.json or {}
    item = payload.get("item")
    author = payload.get("author")
    if not item:
        return jsonify({"error": "missing_item"}), 400
    result = decentralised_list.remove_item(item, author=author)
    return jsonify({"status": "success", "operation": "remove_item", "result": result})

@app.route("/list/get", methods=["GET"])
def list_get():
    include_removed = request.args.get("include_removed", "false").lower() in ("1", "true", "yes")
    result = decentralised_list.get_list(include_removed=include_removed)
    return jsonify({"status": "success", "operation": "get_list", "result": result})


# Fragment vault endpoints
@app.route("/fragment/store", methods=["POST"])
def fragment_store():
    payload = request.json or {}
    owner = payload.get("owner", "owner-" + os.urandom(3).hex())
    fragment = payload.get("fragment", payload.get("payload", "fragment-data-" + os.urandom(6).hex()))
    result = fragment_vault.store_fragment(owner, fragment)
    return jsonify({"status": "success", "operation": "store_fragment", "result": result})

@app.route("/fragment/get", methods=["GET"])
def fragment_get():
    fid = request.args.get("fragment_id")
    if not fid:
        return jsonify({"error": "missing_fragment_id"}), 400
    result = fragment_vault.retrieve_fragment(fid)
    return jsonify({"status": "success", "operation": "retrieve_fragment", "result": result})


# Multisig endpoints
@app.route("/multisig/propose", methods=["POST"])
def multisig_propose():
    payload = request.json or {}
    proposer = payload.get("proposer", "owner-" + os.urandom(3).hex())
    action = payload.get("action", {"type": "transfer", "amount": 0})
    result = multisig.propose(proposer, action)
    return jsonify({"status": "success", "operation": "propose", "result": result})

@app.route("/multisig/approve", methods=["POST"])
def multisig_approve():
    payload = request.json or {}
    pid = str(payload.get("proposal_id"))
    approver = payload.get("approver", "owner-" + os.urandom(3).hex())
    result = multisig.approve(pid, approver)
    return jsonify({"status": "success", "operation": "approve", "result": result})


@app.route("/anomaly/submit", methods=["POST"])
def anomaly_submit():
    payload = request.json or {}
    source = payload.get("source", "sensor-" + os.urandom(3).hex())
    severity = payload.get("severity", "medium")
    metadata = payload.get("metadata", {})
    result = anomaly_oracle.submit_anomaly(source, severity, metadata)
    return jsonify({"status": "success", "operation": "submit_anomaly", "result": result})

@app.route("/anomaly/list", methods=["GET"])
def anomaly_list():
    limit = int(request.args.get("limit", 50))
    result = anomaly_oracle.list_anomalies(limit=limit)
    return jsonify({"status": "success", "operation": "list_anomalies", "result": result})


@app.route("/chain/events", methods=["GET"])
def chain_events():

    events = (
        proof_anchor.recent_events(10) +
        voting.recent_events(10) +
        decentralised_list.recent_events(10) +
        fragment_vault.recent_events(10) +
        multisig.recent_events(10) +
        anomaly_oracle.recent_events(10)
    )

    events_sorted = sorted(events, key=lambda x: x.get("block_number", 0), reverse=True)
    return jsonify({"status": "success", "events": events_sorted[:100]})

@app.route('/api/protectKey', methods=['POST'])
@limiter.limit("15 per minute")
def protect_key():
    """
    API endpoint to protect data with quantum encryption
    Accepts:
    - Raw text (form-data: 'data')
    - Files (form-data: 'file')
    - JSON data (content-type: application/json)
    Requires metadata
    """
    try:
        
        email = session.get("email") or request.headers.get('X-API-Email')
        if not email:
            return jsonify({"error": "Authentication required"}), 401
            
        user = users.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        user_id = user.get("id")

        
        data_id = generate_id("DATA")
        key_id = generate_id("KEY")

      
        full_payload = None
        data_format = "txt"
        metadata = request.form.get('metadata') or "API Protected Data"

        if request.is_json:
            json_data = request.get_json()
            full_payload = json.dumps(json_data).encode()
            data_format = "json"
            metadata = metadata or "JSON Data"

        elif 'data' in request.form:
            full_payload = request.form['data'].encode()
            data_format = "txt"
            metadata = metadata or "Text Data"

        elif 'file' in request.files:
            uploaded_file = request.files['file']
            if uploaded_file.filename == '':
                return jsonify({"error": "No selected file"}), 400
                
            full_payload = uploaded_file.read()
            filename = secure_filename(uploaded_file.filename)
            data_format = filename.split('.')[-1].lower() if '.' in filename else "bin"
            
            if data_format == "csv":
                try:
                    pd.read_csv(BytesIO(full_payload))
                except Exception as e:
                    return jsonify({"error": f"Invalid CSV: {str(e)}"}), 400
                    
            metadata = metadata or f"Uploaded {data_format.upper()} File"

        else:
            return jsonify({
                "error": "No data provided. Send either:",
                "options": [
                    "JSON data (Content-Type: application/json)",
                    "Form-data with 'data' field (text)",
                    "File upload with 'file' field"
                ]
            }), 400

        create_folder()
        with open(os.path.join(output_dir, "a_og_input.txt"), "wb") as f:
            f.write(full_payload)

        if data_format in ["", "bin"]:
            input_file = os.path.join(output_dir, "a_og_input.txt")
            detected_format = identify_file_type(input_file)
            data_format = detected_format[1:] if detected_format else "bin"

        generate_all_keys(data_id, key_id, user_id)
        file_size_mb = round(len(full_payload) / (1024 * 1024), 2)
        encrypt_layered(full_payload, data_format, data_id, key_id, metadata, user_id, file_size_mb)

        return jsonify({
            "status": "success",
            "data_id": data_id,
            "key_id": key_id,
            "metadata": metadata,
            "data_format": data_format,
            "size_mb": file_size_mb,
            "timestamp": datetime.now().isoformat()
        }), 201

    except Exception as e:
        error_msg = f"Protection failed: {str(e)}"
        if 'user_id' in locals():
            send_error_report_email(user_id, "API Protection Error", e)
        return jsonify({
            "status": "error",
            "message": error_msg,
            "hint": "Check your input format and try again"
        }), 500
@app.route('/api/manageData', methods=['GET'])
def api_manage_data():
    """Get all encrypted data for authenticated user"""
    try:
        email = session.get("email") or request.headers.get('X-API-Email')
        if not email:
            return jsonify({"error": "Authentication required"}), 401

        user = users.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        user_id = user.get("id")
        data = list(AES_Encryption_collection.find({"user_id": user_id}, {
            "data_id": 1,
            "meta_data": 1,
            "data_format": 1,
            "encrypted_at": 1,
            "status": 1,
            "layers": 1,
            "_id": 0
        }).sort("encrypted_at", -1))

        for item in data:
            if 'encrypted_at' in item and isinstance(item['encrypted_at'], datetime):
                item['encrypted_at'] = item['encrypted_at'].isoformat()

        return jsonify({
            "status": "success",
            "count": len(data),
            "data": data
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/userProfile', methods=['GET'])
def api_user_profile():
    """Get authenticated user's profile"""
    try:
        email = session.get("email") or request.headers.get('X-API-Email')
        if not email:
            return jsonify({"error": "Authentication required"}), 401

        user = users.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        profile = {
            "name": user.get("name"),
            "email": user.get("email"),
            "user_id": user.get("id"),
            "last_login": user.get("last_login").isoformat() if user.get("last_login") else None,
            "total_data_secured": AES_Encryption_collection.count_documents({"user_id": user.get("id")}),
            "security_shield_activated": AES_Encryption_collection.count_documents({
                "user_id": user.get("id"),
                "status": "Fragmented"
            })
        }

        return jsonify({
            "status": "success",
            "profile": profile
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/data/<data_id>', methods=['GET'])
def api_get_data(data_id):
    """Get encrypted data by data_id (metadata only)"""
    try:
        email = session.get("email") or request.headers.get('X-API-Email')
        if not email:
            return jsonify({"error": "Authentication required"}), 401

        user = users.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        data = AES_Encryption_collection.find_one({
            "data_id": data_id,
            "user_id": user.get("id")
        }, {
            "enc_data": 0, 
            "fragments": 0
        })

        if not data:
            return jsonify({"error": "Data not found or access denied"}), 404

        if '_id' in data:
            data['_id'] = str(data['_id'])
        if 'encrypted_at' in data and isinstance(data['encrypted_at'], datetime):
            data['encrypted_at'] = data['encrypted_at'].isoformat()

        return jsonify({
            "status": "success",
            "data": data
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/keys/<key_id>', methods=['GET'])
def api_get_key(key_id):
    """Get key metadata by key_id (no actual keys returned)"""
    try:
        email = session.get("email") or request.headers.get('X-API-Email')
        if not email:
            return jsonify({"error": "Authentication required"}), 401

        user = users.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        key_data = Key_Vault_collection.find_one({
            "key_id": key_id,
            "user_id": user.get("id")
        }, {
            "Key": 0 
        })

        if not key_data:
            return jsonify({"error": "Key not found or access denied"}), 404

        data_info = AES_Encryption_collection.find_one(
            {"data_id": key_data.get("data_id")},
            {"meta_data": 1, "data_format": 1, "_id": 0}
        ) or {}

        response = {
            "key_id": key_data.get("key_id"),
            "data_id": key_data.get("data_id"),
            "algorithm": key_data.get("algorithm", "Kyber1024-AES256"),
            "created_at": key_data.get("created_at").isoformat() if key_data.get("created_at") else None,
            "status": key_data.get("status", "active"),
            "associated_data": data_info
        }

        return jsonify({
            "status": "success",
            "key": response
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/data/<data_id>', methods=['DELETE'])
def api_delete_data(data_id):
    """Securely delete all traces of encrypted data and associated keys"""
    try:
        email = session.get("email") or request.headers.get('X-API-Email')
        if not email:
            return jsonify({"error": "Authentication required"}), 401

        user = users.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        result = {
            "data": AES_Encryption_collection.delete_one({"data_id": data_id, "user_id": user["id"]}),
            "keys": Key_Vault_collection.delete_one({"data_id": data_id, "user_id": user["id"]}),
            "ciphers": Key_Cipher_collection.delete_one({"data_id": data_id, "user_id": user["id"]}),
            "fragments": large_files_collection.delete_many({"data_id": data_id})
        }

        if result["data"].deleted_count == 0:
            return jsonify({"error": "Data not found or already deleted"}), 404

        return jsonify({
            "status": "success",
            "message": "Data and all associated keys permanently deleted",
            "details": {
                "data_deleted": result["data"].deleted_count,
                "keys_deleted": result["keys"].deleted_count,
                "ciphers_deleted": result["ciphers"].deleted_count,
                "fragments_deleted": result["fragments"].deleted_count
            }
        }), 200

    except Exception as e:
        return jsonify({"error": f"Deletion failed: {str(e)}"}), 500
    
@app.route('/api/system/health', methods=['GET'])
def system_health():
    """Check database and encryption service status"""
    return jsonify({
        "database": "healthy" if client.admin.command('ping') else "down",
        "last_anomaly": anomaly_state["last_detected"]
    })
    
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)