
from flask import Flask, jsonify, request
import jwt

app = Flask(__name__)
SECRET = "lab-secret"
ORDERS = {
    "1001": [{"id": "ord-1", "owner": "1001", "total": 42}],
    "1002": [{"id": "ord-2", "owner": "1002", "total": 99}],
}


def weak_user_id():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None
    try:
        # Intentionally vulnerable lab behavior: signature verification disabled.
        return jwt.decode(token, options={"verify_signature": False}).get("sub")
    except Exception:
        return None


@app.get("/api/v1/health")
def health():
    return jsonify({"status": "ok", "lab": "flask"})


@app.get("/api/v1/profile")
def profile():
    user_id = weak_user_id()
    if not user_id:
        return jsonify({"error": "missing token"}), 401
    return jsonify({"id": user_id, "role": "user"})


@app.get("/api/v1/users/<user_id>/orders")
def user_orders(user_id):
    # Intentionally vulnerable IDOR for local practice.
    return jsonify({"orders": ORDERS.get(user_id, [])})


@app.post("/api/v1/auth/login")
def login():
    # Intentionally missing rate limits for lab demonstrations.
    return jsonify({"error": "invalid credentials"}), 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
