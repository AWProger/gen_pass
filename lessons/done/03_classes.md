# Классы и ООП

## Базовый класс
```python
class PasswordManager:
    def __init__(self):        # конструктор — вызывается при создании объекта
        self.history = []      # атрибут объекта

    def gen_password(self, length=16):  # метод — self всегда первый параметр
        ...
        return password_str
```

## self
self — это ссылка на сам объект. Через self обращаемся к атрибутам и методам.

## Создание объекта
```python
manager = PasswordManager()   # создаём объект
manager.gen_password(16)      # вызываем метод
```

## Инкапсуляция
Данные (history) и методы (gen_password, get_history) живут вместе в классе.
Снаружи не нужно знать как устроена история — просто вызываешь get_history().

## Глобальная переменная vs атрибут класса
```python
# плохо — глобальная переменная
history = []

# хорошо — атрибут класса
class PasswordManager:
    def __init__(self):
        self.history = []
```
