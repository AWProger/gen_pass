# Функции

## Базовая функция
```python
def gen_password(length=16, digits=True, symbols=True):
    # код
    return password_str
```

## Параметры по умолчанию
```python
def gen_password(length=16):  # если не передать length — будет 16
```

## *args и **kwargs
```python
def func(*args):       # принимает любое количество позиционных аргументов
def func(**kwargs):    # принимает любое количество именованных аргументов

# пример использования в проекте
def edit_by_id(self, record_id, **kwargs):
    e.update(kwargs)   # kwargs это словарь переданных аргументов
```

## return
Функция возвращает значение через return. Без return — возвращает None.

## Вложенные функции
```python
def run_app():
    def generate():   # generate живёт внутри run_app
        ...           # имеет доступ к переменным run_app (closure)
```
