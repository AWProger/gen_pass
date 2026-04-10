# Flask и REST API

## Основы Flask
```python
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.route("/")                    # GET запрос на /
def home():
    return render_template("index.html")

@app.route("/api/generate", methods=["POST"])   # POST запрос
def api_generate():
    data = request.json            # получаем JSON из тела запроса
    return jsonify({"password": "..."})  # возвращаем JSON

if __name__ == "__main__":
    app.run(debug=True)
```

## HTTP методы
```
GET    — получить данные
POST   — создать/отправить данные
PUT    — обновить данные
DELETE — удалить данные
```

## URL параметры
```python
@app.route("/api/delete/<record_id>", methods=["DELETE"])
def api_delete(record_id):         # record_id приходит из URL
    manager.delete_by_id(record_id)
    return jsonify({"status": "ok"})
```

## Структура проекта Flask
```
app.py           — сервер и routes
core.py          — бизнес-логика
templates/       — HTML файлы
static/          — CSS, JS, изображения
```

## JavaScript fetch
```javascript
const response = await fetch('/api/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ length: 16 })
});
const data = await response.json();
```
