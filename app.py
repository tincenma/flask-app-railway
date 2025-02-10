from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
import os
import datetime
from dotenv import load_dotenv
from bson.objectid import ObjectId
from chatbot import create_thread, delete_thread, add_message_to_thread, get_thread_messages, run_assistant

load_dotenv()

app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET")

mongo = PyMongo(app)
jwt = JWTManager(app)
CORS(app)

# Лимитер
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["50 per day", "10 per hour"]
)

@app.route('/')
def index():
    return "Flask API is running!"

@app.route('/test', methods=['GET'])
def test():
    return jsonify({"message": "Server is running!"})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    required_fields = ['fullname', 'email', 'password', 'mobile']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    if mongo.db.users.find_one({"email": data['email']}):
        return jsonify({"error": "Email already exists"}), 409

    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    user_data = {
        "fullname": data['fullname'],
        "email": data['email'],
        "password": hashed_password,
        "mobile": data['mobile'],
        "structunit": data.get('structunit', ''),
        "dob": data.get("dob", ""),
        "city": data.get("city", ""),
        "address": data.get("address", ""),
        "created_at": datetime.datetime.utcnow()
    }

    try:
        mongo.db.users.insert_one(user_data)
        return jsonify({"success": True}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = mongo.db.users.find_one({"email": email})
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        access_token = create_access_token(identity=str(user['_id']))
        return jsonify(access_token=access_token)
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        user_id = get_jwt_identity()
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "fullname": user.get("fullname"),
            "email": user.get("email"),
            "mobile": user.get("mobile"),
            "structunit": user.get("structunit", ""),
            "dob": user.get("dob", ""),
            "city": user.get("city", ""),
            "address": user.get("address", "")
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        # Email uniqueness check
        if 'email' in data:
            existing_user = mongo.db.users.find_one({
                "email": data['email'],
                "_id": {"$ne": ObjectId(user_id)}
            })
            if existing_user:
                return jsonify({"error": "Email already in use"}), 400

        # Prepare update data
        update_fields = {
            "fullname": data.get("fullname"),
            "email": data.get("email"),
            "mobile": data.get("mobile"),
            "dob": data.get("dob"),
            "city": data.get("city"),
            "address": data.get("address")
        }

        # Remove None values
        update_data = {k: v for k, v in update_fields.items() if v is not None}
        
        # Update database
        result = mongo.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )
        
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

### 🔹 API ЗАЩИЩЕННЫЕ JWT
@app.route('/create-thread', methods=['POST'])
@jwt_required()
def handle_create_thread():
    """Создает новый тред и возвращает его ID (Только для авторизованных пользователей)."""
    try:
        thread_id = create_thread()
        return jsonify({"thread_id": thread_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/chat', methods=['POST'])
@jwt_required()
@limiter.limit("10/minute")
def handle_chat():
    """Обрабатывает сообщение пользователя и возвращает ответ ассистента (Только для авторизованных)."""
    try:
        data = request.json
        user_message = data['message']
        thread_id = data['thread_id']

        # Добавляем сообщение пользователя в тред
        add_message_to_thread(thread_id, user_message)

        # Запускаем ассистента
        assistant_response = run_assistant(thread_id)

        return jsonify({"status": "success", "response": assistant_response})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/get-messages/<thread_id>', methods=['GET'])
@jwt_required()
@limiter.limit("20/minute")
def handle_get_messages(thread_id):
    """Возвращает историю сообщений (Только для авторизованных)."""
    try:
        messages = get_thread_messages(thread_id)
        return jsonify(messages)
    except Exception as e:
        error_message = str(e)
        if "не найден" in error_message.lower():
            return jsonify({"error": "Тред не найден"}), 404
        return jsonify({"error": error_message}), 500

@app.route('/delete-thread/<thread_id>', methods=['DELETE'])
@jwt_required()
def handle_delete_thread(thread_id):
    """Удаляет указанный тред (Только для авторизованных)."""
    try:
        delete_thread(thread_id)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)