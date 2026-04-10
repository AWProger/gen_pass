# Декораторы

## Что такое декоратор
Функция которая оборачивает другую функцию, добавляя ей новое поведение.

## Создание декоратора
```python
def log_call(func):
    def wrapper(*args, **kwargs):
        print(f"Вызов: {func.__name__}")  # добавляем логирование
        return func(*args, **kwargs)       # вызываем оригинальную функцию
    return wrapper
```

## Применение
```python
@log_call
def gen_password(self, length=16):
    ...
# теперь каждый вызов gen_password выводит "Вызов: gen_password"
```

## *args, **kwargs в wrapper
Нужны чтобы декоратор работал с любой функцией независимо от её параметров.

## Встроенные декораторы Python
```python
@property          # геттер
@classmethod       # метод класса (первый параметр cls, не self)
@staticmethod      # статический метод (без self и cls)
@dataclass         # автогенерация __init__, __repr__, __eq__
```
