from openai import OpenAI
import os
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
ASSISTANT_ID = os.getenv("ASSISTANT_ID")

def create_thread():
    """Создает новый тред и возвращает его ID."""
    thread = client.beta.threads.create()
    return thread.id

def delete_thread(thread_id):
    """Удаляет тред по его ID."""
    client.beta.threads.delete(thread_id)

def add_message_to_thread(thread_id, user_message):
    """Добавляет сообщение пользователя в указанный тред."""
    client.beta.threads.messages.create(
        thread_id=thread_id,
        role="user",
        content=user_message
    )

def get_thread_messages(thread_id):
    """Возвращает историю сообщений для указанного треда."""
    try:
        messages = client.beta.threads.messages.list(
            thread_id=thread_id,
            order='asc'
        )
        formatted_messages = []
        for msg in messages.data:
            # Обрабатываем возможные ошибки структуры сообщений
            try:
                content = msg.content[0].text.value
            except (IndexError, AttributeError):
                content = "[Неизвестный формат сообщения]"
                
            formatted_messages.append({
                "role": msg.role,
                "content": content,
                "created_at": msg.created_at
            })
        return formatted_messages
    except Exception as e:
        raise Exception(f"Ошибка получения сообщений: {str(e)}")

def run_assistant(thread_id):
    """Запускает ассистента для обработки сообщений в указанном треде."""
    run = client.beta.threads.runs.create(
        thread_id=thread_id,
        assistant_id=ASSISTANT_ID
    )

    # Ожидаем завершения выполнения ассистента
    while True:
        run_status = client.beta.threads.runs.retrieve(
            thread_id=thread_id,
            run_id=run.id
        )
        if run_status.status == 'completed':
            break

    # Получаем последний ответ ассистента
    messages = client.beta.threads.messages.list(
        thread_id=thread_id,
        order='desc',
        limit=1
    )
    assistant_message = messages.data[0].content[0].text.value
    return assistant_message