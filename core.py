import secrets
import string
import json 
import uuid

from datetime import datetime


def log_call(func):        # декоратор — снаружи класса
    def wrapper(*args, **kwargs):
        print(f"Вызов: {func.__name__}")
        return func(*args, **kwargs)
    return wrapper

class PasswordManager ():

    def __init__(self):
        self.history = [] 

    @log_call
    def gen_password(self, length=16, digits=True, symbols=True, site="", login="", email=""):
        if length < 4:
            raise ValueError("Минимальная длина 4")

        chars = list(string.ascii_letters)

        if digits:
            chars += list(string.digits)
        if symbols:
            chars += list(string.punctuation)

        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase)
        ]

        if digits:
            password.append(secrets.choice(string.digits))
        if symbols:
            password.append(secrets.choice(string.punctuation))

        password += [secrets.choice(chars) for _ in range(length - len(password))]

        secrets.SystemRandom().shuffle(password)
        
        password_str = ''.join(password)  # собираем список в строку
        self.history.append({
            "id": str(uuid.uuid4()),
            "site": site,
            "login": login,
            "email": email,
            "password": password_str,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M")
        })
     # добавляем строку в историю
        return password_str     
    @log_call
    def get_history(self):
        return self.history.copy()

    @log_call
    def check_strength(self, password):
        has_digit = any(c.isdigit() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        if len(password) < 8:
            return "Слабый"
        if len(password) >= 12 and has_digit and has_upper and has_symbol:
            return "Сильный"
        return "Средний"

    @log_call
    def save_history(self, filename):
        with open(filename, "w") as f:
            json.dump(self.history, f)

    @log_call
    def load_history(self, filename):
        with open(filename, "r") as f:
            self.history = json.load(f)

    @log_call
    def clear_history(self):
        self.history.clear()

    def search(self, query):
        query = query.lower()
        return [e for e in self.history if 
                query in e["site"].lower() or 
                query in e["login"].lower() or 
                query in e["email"].lower()]

    @log_call
    def delete_by_id(self, record_id):
        self.history = [e for e in self.history if e["id"] != record_id]

    @log_call
    def edit_by_id(self, record_id, **kwargs):
        for e in self.history:
            if e["id"] == record_id:
                e.update(kwargs)
                break
