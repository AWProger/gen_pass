import secrets
import string
import json 


history = []

def gen_password(length=16, digits=True, symbols=True):
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
    history.append(password_str)      # добавляем строку в историю
    return password_str     

def get_history():
    return history.copy()

def check_strength(password):
    has_digit = any(c.isdigit() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    if len(password) < 8:
        return "Слабый"
    if len(password) >= 12 and has_digit and has_upper and has_symbol:
        return "Сильный"
    return "Средний"

def save_history(filename):
    with open(filename, "w") as f:
        json.dump(history, f)


def load_history(filename):
    global history
    with open(filename, "r") as f:
        history = json.load(f)
