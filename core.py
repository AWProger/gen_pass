import secrets
import string

import json 

class PasswordManager ():
    def __init__(self):
        self.history = [] 

    def gen_password(self, length=16, digits=True, symbols=True):
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
        self.history.append(password_str)      # добавляем строку в историю
        return password_str     

    def get_history():
        return self.history.copy()

    def check_strength(self, password):
        has_digit = any(c.isdigit() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        if len(password) < 8:
            return "Слабый"
        if len(password) >= 12 and has_digit and has_upper and has_symbol:
            return "Сильный"
        return "Средний"

    def save_history(self, filename):
        with open(filename, "w") as f:
            json.dump(self.history, f)


    def load_history(self, filename):
        with open(filename, "r") as f:
            self.history = json.load(f)

    def clear_history():
        self.history.clear()
        
