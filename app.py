from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import bcrypt
import os
from dotenv import load_dotenv
from chatbot import create_thread, delete_thread, add_message_to_thread, get_thread_messages, run_assistant

load_dotenv()

app = Flask(__name__)

# Конфиг для JWT
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET", "super-secret-key")  # Лучше хранить в .env
jwt = JWTManager(app)

app.config.update({
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'SESSION_COOKIE_SECURE': True,
    'JWT_COOKIE_SECURE': True,
    'JWT_COOKIE_SAMESITE': 'Lax'
})

# Разрешить доступ только с фронтенда
CORS(app)

# Инициализация лимитера
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["50 per day", "10 per hour"]
)

# Простая база пользователей (лучше заменить на БД)
users_db = {
    "admin@khc.kz": {
        "password": bcrypt.hashpw("1234".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    }
}

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    response.headers['Access-Control-Expose-Headers'] = 'Authorization'
    return response

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Необходимо указать email и пароль"}), 400

    user = users_db.get(email)
    if not user:
        return jsonify({"error": "Неверные учетные данные"}), 401

    if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        access_token = create_access_token(identity=email)
        return jsonify(access_token=access_token)
    
    return jsonify({"error": "Неверные учетные данные"}), 401

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
@limiter.limit("5/minute")
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

@app.route('/test', methods=['GET'])
def test():
    return jsonify({"message": "Server is running!"})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
