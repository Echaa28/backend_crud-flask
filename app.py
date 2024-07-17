import datetime
import random
import secrets
from ssl import VerifyMode
import string
from flask import Flask, request, jsonify, Response, render_template, send_file
from flask_login import LoginManager, login_required, UserMixin, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename
import cv2
from ultralytics import YOLO
from pymongo import MongoClient
import logging
from bson.objectid import ObjectId
from flask import Flask, request, redirect, url_for, flash, render_template
from flask_mail import Mail, Message
from itsdangerous import BadSignature, URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_mail import Message
import random
import string
from secrets import token_hex

# Enable logging for debugging
logging.basicConfig(level=logging.INFO)

# Flask app initialization
app = Flask(__name__)

# Enable CORS
CORS(app)

# Configuration
app.config['SECRET_KEY'] = '9OLWxND4o83j4K4iuopO'
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this to a random secret key
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_PATH'] = 16 * 1024 * 1024  # 16 MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'aldi.bhaz10@gmail.com'
app.config['MAIL_PASSWORD'] = 'xlywdnkwpubrausg'

mail = Mail(app)
s = URLSafeTimedSerializer('your_secret_key')

# Initialize MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db_mongo = client['bisindo_color']
user_collection = db_mongo['users']
color_collection = db_mongo['color']

# Login manager setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# JWT manager setup
jwt = JWTManager(app)

# User model using MongoDB
class User(UserMixin):
    def __init__(self, user_dict):
        self.id = str(user_dict['_id'])
        self.email = user_dict['email']
        self.password = user_dict['password']
        self.name = user_dict['name']
        self.profile_picture = user_dict.get('profile_picture')
        self.is_verified = user_dict.get('is_verified', False)
        self.verification_token = user_dict.get('verification_token')

    @staticmethod
    def get(user_id):
        user = user_collection.find_one({'_id': ObjectId(user_id)})
        if user:
            return User(user)
        return None

    @staticmethod
    def get_by_email(email):
        user = user_collection.find_one({'email': email})
        if user:
            return User(user)
        return None

    @staticmethod
    def create(email, name, password):
        user_dict = {
            'email': email,
            'name': name,
            'password': generate_password_hash(password, method='pbkdf2:sha256'),
            'profile_picture': None,
            'is_verified': False,
            'verification_token': None
        }
        result = user_collection.insert_one(user_dict)
        return User(user_collection.find_one({'_id': result.inserted_id}))

    def save(self):
        user_collection.update_one(
            {'_id': ObjectId(self.id)},
            {'$set': {
                'email': self.email,
                'name': self.name,
                'profile_picture': self.profile_picture,
                'is_verified': self.is_verified,
                'verification_token': self.verification_token
            }}
        )


# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.get_by_email(email)

    if not user or not check_password_hash(user.password, password):
        message = 'Please check your login details and try again.'
        return jsonify({'message': message}), 400

    if not user.is_verified:
        return jsonify({'message': 'Please verify your email before logging in.'}), 403

    login_user(user)
    access_token = create_access_token(identity=user.id)
    return jsonify({'message': 'Login successful', 'access_token': access_token}), 200


@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    name = data.get('name')
    password = data.get('password')

    if User.get_by_email(email):
        message = 'Email address already exists'
        return jsonify({'message': message}), 400

    verification_token = token_hex(3)  # This generates a 6-character token
    new_user = User.create(email, name, password)
    new_user.is_verified = False
    new_user.verification_token = verification_token
    new_user.save()

    confirmation_url = url_for('confirm_email', token=verification_token, _external=True)
    msg = Message(subject="Verify your email", sender="aldi.bhaz10@gmail.com", recipients=[email])
    msg.body = f'Please click the link to confirm your email: {confirmation_url}'
    mail.send(msg)

    return jsonify({'message': 'User created successfully. Please check your email to confirm your registration.'}), 200

@app.route('/confirm_email/<token>', methods=['GET'])
def confirm_email(token):
    user = user_collection.find_one({"verification_token": token})
    if not user:
        return jsonify({"message": "Invalid or expired token."}), 404

    if user.get("is_verified"):
        return jsonify({"message": "Account already verified."}), 200

    user_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"is_verified": True, "verification_token": None}}
    )
    return jsonify({"message": "Email successfully verified."}), 200

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/edit_profile', methods=['PUT'])
@jwt_required()
def edit_profile():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    
    current_user_id = get_jwt_identity()
    current_user = User.get(current_user_id)

    # Handling profile picture upload
    file = request.files.get('profile_picture')
    if file and allowed_file(file.filename): # type: ignore
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        current_user.profile_picture = filename

    current_user.name = name
    current_user.email = email

    current_user.save()
    return jsonify({'message': 'Profile updated successfully.'}), 200

@app.route('/change_password', methods=['POST'])
@jwt_required()
def change_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    current_user_id = get_jwt_identity()
    current_user = User.get(current_user_id)

    if not check_password_hash(current_user.password, current_password):
        return jsonify({'error': 'Current password is incorrect.'}), 400

    if new_password != confirm_password:
        return jsonify({'error': 'New passwords do not match.'}), 400

    # Update the password in the database
    current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
    
    # Save the updated user details to the database
    user_collection.update_one(
        {'_id': ObjectId(current_user_id)},
        {'$set': {'password': current_user.password}}
    )

    return jsonify({'message': 'Password changed successfully.'}), 200

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/upload_profile', methods=['POST'])
@jwt_required()
def upload_profile():
    if 'profile_picture' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    current_user_id = get_jwt_identity()
    current_user = User.get(current_user_id)

    file = request.files['profile_picture']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename): # type: ignore
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Update the user's profile picture
        current_user.profile_picture = filename
        current_user.save()

        return jsonify({'message': 'Profile picture updated successfully.'}), 200

    return jsonify({'error': 'Invalid file type.'}), 400

@app.route('/upload_profile/<filename>', methods=['GET'])
def get_profile_picture(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path)
    else:
        return jsonify({'error': 'File not found'}), 404

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.get(current_user_id)
    profile_picture_url = f"http://172.20.10.9:5000/upload_profile/{user.profile_picture}"
    return jsonify(
        name=user.name,
        email=user.email,
        profile_picture=profile_picture_url
    ), 200

@app.route('/test_db')
def test_db():
    try:
        # Attempt to connect to the MongoDB database
        client.server_info()  # This will throw an exception if the database is not reachable
        return jsonify({'message': 'Database connection successful'}), 200
    except Exception as e:
        # Log and return the error message
        logging.error(f"Error connecting to the database: {e}")
        return jsonify({'message': 'Database connection failed', 'error': str(e)}), 500

# Load YOLO model
model = YOLO('model/best.pt')

def save_to_mongodb(predictions, color_collection, gender):
    logging.info(f"Saving detections to MongoDB, gender: {gender}")
    for result in predictions:
        if result.boxes is not None and len(result.boxes) > 0:
            for box in result.boxes:
                class_index = int(box.cls[0])
                class_name = model.names[class_index]
                document = {
                    "class_name": class_name,
                    "gender": gender,
                    "detection_date": datetime.datetime.now()
                }
                try:
                    color_collection.insert_one(document)
                    logging.info(f"Successfully saved detection: {document}")
                except Exception as e:
                    logging.error(f"Error saving to MongoDB: {e}")

def detect_objects(gender):
    cap = cv2.VideoCapture(0) 

    if not cap.isOpened():
        logging.error("Error: Could not open video stream.")
        return

    while True:
        ret, frame = cap.read()

        if not ret:
            logging.error("Error: Failed to read frame from video stream.")
            break

        # Perform object detection on the frame
        results = model(frame)

        # Save detections to MongoDB
        save_to_mongodb(results, color_collection, gender)

        # Draw bounding boxes on the frame
        for result in results:
            if result.boxes is not None and len(result.boxes) > 0:
                for box in result.boxes:
                    class_index = int(box.cls[0])
                    class_name = model.names[class_index]
                    confidence = box.conf[0]

                    # Get bounding box coordinates
                    x1, y1, x2, y2 = map(int, box.xyxy[0])

                    # Draw bounding box and label on the frame
                    color = (0, 255, 0)
                    cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
                    label = f"{class_name}: {confidence:.2f}"
                    cv2.putText(frame, label, (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)

        # Encode the frame as JPEG
        ret, jpeg = cv2.imencode('.jpg', frame)
        if ret:
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + jpeg.tobytes() + b'\r\n')

    cap.release()
    cv2.destroyAllWindows()

@app.route('/video_feed')
def video_feed():
    gender = request.args.get('gender', default='unknown')
    return Response(detect_objects(gender), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/realtime')
def realtime():
    return render_template('video.html')

def generate_verification_code():
    # Implement your code to generate a verification code
    pass

def save_verification_code(email, verification_code):
    # Implement your code to save the verification code to the database
    pass

def save_verification_code(email, verification_code):
    user_collection.update_one({'email': email}, {'$set': {'otp': verification_code}})


def generate_random_token():
    return secrets.token_urlsafe(16)

@app.route('/request_reset_password', methods=['POST'])
def request_reset_password():
    data = request.get_json()
    email = data.get('email')

    user = User.get_by_email(email)

    if not user:
        return jsonify({'message': 'Email address not found.'}), 404

    reset_token = token_hex(3)  # This generates a 6-character token
    user.verification_token = reset_token
    user.save()

    reset_url = url_for('reset_password', token=reset_token, _external=True)
    msg = Message(subject="Reset Your Password", sender="aldi.bhaz10@gmail.com", recipients=[email])
    msg.body = f'Please click the link to reset your password: {reset_url}'
    mail.send(msg)

    return jsonify({'message': 'Password reset email sent. Please check your email.'}), 200

@app.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    data = request.get_json()
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if new_password != confirm_password:
        return jsonify({'message': 'Passwords do not match.'}), 400

    user = user_collection.find_one({"verification_token": token})

    if not user:
        return jsonify({"message": "Invalid or expired token."}), 404

    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
    user_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"password": hashed_password, "verification_token": None}}
    )

    return jsonify({'message': 'Password has been reset successfully.'}), 200


if __name__ == '__main__':
    app.run(debug=True, host="172.20.10.9")
