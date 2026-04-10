# Файлы и JSON

## Открытие файла
```python
with open("file.txt", "w") as f:   # w — запись, r — чтение, rb — бинарное чтение
    f.write("текст")
# файл закрывается автоматически после блока with
```

## JSON
```python
import json

# список/словарь → JSON файл
with open("data.json", "w") as f:
    json.dump(self.history, f)

# JSON файл → список/словарь
with open("data.json", "r") as f:
    self.history = json.load(f)

# список/словарь → JSON строка
json_str = json.dumps(self.history)

# JSON строка → список/словарь
data = json.loads(json_str)
```

## Шифрованный файл
```python
# сохранение с шифрованием
json_str = json.dumps(self.history)
encrypted = self.f.encrypt(json_str.encode())
with open(filename, "wb") as f:   # wb — бинарная запись
    f.write(encrypted)

# загрузка с расшифровкой
with open(filename, "rb") as f:   # rb — бинарное чтение
    encrypted = f.read()
json_str = self.f.decrypt(encrypted).decode()
self.history = json.loads(json_str)
```
