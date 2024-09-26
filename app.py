import logging
from logstash_formatter import LogstashFormatterV1
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps

# Set up logging
logger = logging.getLogger('logstash')
logger.setLevel(logging.INFO)
logstash_handler = logging.FileHandler('logstash.log')
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
pqrs = [
    {"id": "d03b5a72-58e1-4b3c-9c30-d3164095a5f4", "userId": 123, "msg": "Error en login"},
    {"id": "88cfb4dd-7147-42d9-bb83-1b2a867ee121", "userId": 124, "msg": "Error en en calculo de intereses"}
]

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
    
def role_required(required_roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user = get_jwt_identity()
            user_roles = user.get('roles', [])
            logger.info("Request received", extra={
                'request_method': request.method,
                'request_path': request.path,
                'user': user.get('username'),
                'headers': dict(request.headers)
            })
            if any(role in user_roles for role in required_roles):
                return fn(*args, **kwargs)
            return jsonify({"msg": "Access denied"}), 403
        return wrapper
    return decorator

@app.route('/getPQR/<pqr_id>', methods=['GET'])
@role_required(['gestor','user'])
def get_pqr(pqr_id):
    user = get_jwt_identity()
    username = user.get('username')
    roles = user.get('roles', [])
    for pqr in pqrs:
        if pqr['id'] == pqr_id:
            if 'gestor' not in roles and pqr['userId'] != users[username]['userId']:
                response = jsonify({"msg": "Access denied"}), 403
                logger.error("Response", extra={'response': response})
                return response
            response = jsonify({"msg": pqr["msg"], "pqr_id": pqr["id"]})
            logger.info("Response", extra={'response': response})
            return response

    response = jsonify({"msg": "PQR not found"}), 404
    logger.error("Response", extra={'response': response})
    return response

if __name__ == '__main__':
    app.run(port=9090)