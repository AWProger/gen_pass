# Исключения

## Типы ошибок
```python
ValueError      # неправильное значение — int("abc")
TypeError       # неправильный тип — "abc" + 5
FileNotFoundError  # файл не найден
ZeroDivisionError  # деление на ноль
KeyError        # ключ не найден в словаре
IndexError      # индекс за пределами списка
```

## try/except
```python
try:
    length = int(length_var.get())   # может бросить ValueError
except ValueError as e:
    messagebox.showerror("Ошибка", str(e))
```

## Бросить ошибку
```python
def gen_password(self, length=16):
    if length < 4:
        raise ValueError("Минимальная длина 4")  # бросаем ошибку
```

## Ловить конкретно vs всё
```python
except Exception:    # ловит всё — плохая практика, скрывает баги
except ValueError:   # ловит только ValueError — правильно
```

## finally
```python
try:
    f = open("file.txt")
except FileNotFoundError:
    print("Файл не найден")
finally:
    f.close()  # выполнится всегда
```
