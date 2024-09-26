import logging
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token
from functools import wraps

# Set up logging
logger = logging.getLogger('logstash')
logger.setLevel(logging.INFO)
logstash_handler = logging.StreamHandler()
logstash_handler.setFormatter(LogstashFormatterV1())
logger.addHandler(logstash_handler)

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
jwt = JWTManager(app)

# Mock database
users = {
    "gestor": {"userId": 1, "password": "gestor", "roles": ["gestor"]},
    "user": {"userId": 123, "password": "user", "roles": ["user"]},
    "user2": {"userId": 124, "password": "user", "roles": ["user"]}
}

# Login route to get a token
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    user = users.get(username, None)
    if user and user['password'] == password:
        access_token = create_access_token(identity={"username": username, "roles": user['roles']})
        return jsonify(access_token=access_token)
    return jsonify({"msg": "Bad username or password"}), 401
    


if __name__ == '__main__':
    app.run(port=9090)