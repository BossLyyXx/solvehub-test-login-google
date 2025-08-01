import os
import datetime
import jwt
import json
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from functools import wraps
from flask import Flask, jsonify, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# --- App Configuration ---
app = Flask(__name__)

# --- ปรับปรุงการตั้งค่า CORS ให้ปลอดภัยขึ้น ---
# อนุญาตเฉพาะ Frontend URL ของคุณเท่านั้น (ทั้งตอนพัฒนาและตอนใช้งานจริง)
origins = [
    "https://solvehub1.vercel.app",
    "http://127.0.0.1:5500",
    "http://localhost:5500"
]
CORS(app, resources={r"/api/*": {"origins": origins}})

basedir = os.path.abspath(os.path.dirname(__file__))

# --- ปรับปรุง SECRET_KEY ให้ปลอดภัยขึ้น ---
# สำคัญ: ในการใช้งานจริง ต้องตั้งค่า SECRET_KEY ใน Environment Variables ของ Render
# ใช้ os.urandom(24).hex() เพื่อสร้างค่าเริ่มต้นที่ปลอดภัยสำหรับการทดสอบ
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'c8a2a0a2a0d9b8e1a8f0e9d8c7b6a5a4b3c2d1e0f9a8b7c6')

DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace("postgres://", "postgresql://", 1)
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID_HERE')

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
db = SQLAlchemy(app)


# --- ส่วนที่เพิ่มเข้ามา: การตั้งค่า HTTP Security Headers ---
@app.after_request
def add_security_headers(response):
    # Content Security Policy (CSP)
    csp = (
        "default-src 'self';"
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://apis.google.com https://accounts.google.com;"
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com;"
        "img-src 'self' data: https:;" # อนุญาต data: และ https: ทั้งหมดสำหรับรูปภาพ
        "font-src 'self' https://cdnjs.cloudflare.com;"
        "connect-src 'self' https://accounts.google.com;" # อนุญาตให้เชื่อมต่อไปยัง Google
        "frame-src 'self' https://accounts.google.com;" # อนุญาต iframe จาก Google Sign-In
        "object-src 'none';"
        "base-uri 'self';"
        "form-action 'self';"
    )
    response.headers['Content-Security-Policy'] = csp.replace("\n", "")
    
    # Strict-Transport-Security (HSTS)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # X-Frame-Options
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # X-Content-Type-Options
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Referrer-Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions-Policy
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    
    return response
# --- จบส่วนที่เพิ่ม ---


# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    picture_url = db.Column(db.String(255), nullable=True)
    
    solutions = db.relationship('Solution', backref='creator', lazy=True)
    login_history = db.relationship('LoginHistory', backref='user', lazy=True)
    activity_logs = db.relationship('ActivityLog', backref='user', lazy=True)

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)
    
    def to_dict(self): 
        return {
            "id": self.id, 
            "username": self.username, 
            "role": self.role,
            "picture_url": self.picture_url
        }

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    icon = db.Column(db.String(20), nullable=True)
    solutions = db.relationship('Solution', backref='subject', lazy=True, cascade="all, delete-orphan")
    def to_dict(self): return {"id": self.id, "name": self.name, "icon": self.icon}
    
class Solution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(300), nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def to_dict_public(self): 
        return {
            "id": self.id, "title": self.title, "date": self.date_created.strftime("%d %b %Y"),
            "creator_username": self.creator.username if self.creator else "N/A"
        }
    def to_dict_detail(self): return {"id": self.id, "title": self.title, "content": self.content, "file_path": self.file_path, "subject_id": self.subject_id}
    def to_dict_admin(self): 
        return {
            "id": self.id, "title": self.title, "subjectName": self.subject.name if self.subject else "N/A", 
            "date": self.date_created.strftime("%d %b %Y"), "subject_id": self.subject_id, "content": self.content, 
            "file_path": self.file_path, "creator_username": self.creator.username if self.creator else "N/A"
        }

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def to_dict(self):
        return {
            "id": self.id, "username": self.user.username, "ip_address": self.ip_address,
            "user_agent": self.user_agent, "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def to_dict(self):
        return {
            "id": self.id, "username": self.user.username, "action": self.action,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }

def log_activity(user, action):
    log = ActivityLog(user_id=user.id, action=action)
    db.session.add(log)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'authorization' in request.headers: token = request.headers['authorization'].split(" ")[1]
        if not token: return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['id'])
            if not current_user: return jsonify({'message': 'User not found!'}), 401
        except Exception as e: return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin': return jsonify({'message': 'Admin role required!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

def moderator_or_admin_required(f):
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if current_user.role not in ['admin', 'moderator']: return jsonify({'message': 'Admin or Moderator role required!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/uploads/<filename>')
def uploaded_file(filename): return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'): return jsonify({"message": "Missing credentials"}), 400
    user = User.query.filter_by(username=data.get('username')).first()
    if user and user.check_password(data.get('password')):
        login_log = LoginHistory(
            user_id=user.id, ip_address=request.remote_addr, 
            user_agent=request.headers.get('User-Agent', 'Unknown')
        )
        db.session.add(login_log)
        db.session.commit()

        token = jwt.encode({'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"access_token": token, "user": user.to_dict()}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/api/login/google', methods=['POST'])
def google_login():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({"message": "Missing Google token"}), 400

    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID'])

        email = idinfo.get('email')
        if not email or not email.endswith('@rmutsvmail.com'):
            return jsonify({"message": "การเข้าสู่ระบบจำกัดเฉพาะอีเมล @rmutsvmail.com เท่านั้น"}), 403

        username = email.split('@')[0]
        picture_url = idinfo.get('picture')
        
        user = User.query.filter_by(username=username).first()

        if not user:
            new_user = User(
                username=username, 
                role='user', 
                picture_url=picture_url
            )
            new_user.set_password(os.urandom(16).hex())
            db.session.add(new_user)
            db.session.commit()
            user = new_user
            log_activity(user, f"สร้างบัญชีใหม่และเข้าสู่ระบบผ่าน Google")
        else:
            user.picture_url = picture_url
            db.session.commit()

        login_log = LoginHistory(
            user_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Google Sign-In')
        )
        db.session.add(login_log)
        db.session.commit()

        jwt_token = jwt.encode(
            {'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
            app.config['SECRET_KEY'],
            algorithm="HS256"
        )
        return jsonify({"access_token": jwt_token, "user": user.to_dict()}), 200

    except ValueError:
        return jsonify({"message": "Invalid Google token"}), 401
    except Exception as e:
        app.logger.error(f"Google login error: {e}")
        return jsonify({"message": "An internal error occurred"}), 500

@app.route('/api/subjects', methods=['GET'])
def get_public_subjects(): return jsonify([s.to_dict() for s in Subject.query.order_by(Subject.name).all()])

@app.route('/api/subjects/<int:subject_id>/solutions', methods=['GET'])
def get_solutions_for_subject(subject_id): return jsonify([s.to_dict_public() for s in Solution.query.filter_by(subject_id=subject_id).order_by(Solution.date_created.desc()).all()])

@app.route('/api/solutions/<int:solution_id>', methods=['GET'])
def get_solution_detail(solution_id): return jsonify(Solution.query.get_or_404(solution_id).to_dict_detail())

# ... (โค้ดส่วน Admin และ Moderator เหมือนเดิม) ...

def setup_database(app):
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first(): 
            print("Creating initial users...")
            admin_user=User(username='admin', role='admin'); admin_user.set_password('admin123')
            mod_user=User(username='moderator', role='moderator'); mod_user.set_password('mod123')
            db.session.add(admin_user); db.session.add(mod_user)
            db.session.commit(); 
            print("Admin and Moderator users created.")

setup_database(app)

if __name__ == '__main__':
    app.run(debug=True)
