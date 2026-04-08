from flask import Flask, render_template, request, jsonify
from core import PasswordManager

app = Flask(__name__)
manager = PasswordManager()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/generate", methods=["POST"])
def api_generate():
    data = request.json
    password = manager.gen_password(
        length=data.get("length", 16),
        digits=data.get("digits", True),
        symbols=data.get("symbols", True),
        site=data.get("site", ""),
        login=data.get("login", ""),
        email=data.get("email", "")
    )
    return jsonify({"password": password})

@app.route("/api/history", methods=["GET"])
def api_history():
    return jsonify(manager.get_history())

@app.route("/api/search", methods=["POST"])
def api_search():
    data = request.json
    return jsonify(manager.search(data.get("query", "")))
    
@app.route("/api/delete/<record_id>", methods=["DELETE"])
def api_delete(record_id):
    manager.delete_by_id(record_id)
    return jsonify({"status": "ok"})

@app.route("/api/edit/<record_id>", methods=["PUT"])
def api_edit(record_id):
    data = request.json
    manager.edit_by_id(record_id, **data)
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(debug=True)
