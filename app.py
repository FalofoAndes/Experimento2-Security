import logging
from logstash_formatter import LogstashFormatterV1
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token
from sqlalchemy.exc import IntegrityError

from modelos import db, Usuario

# Set up logging
logger = logging.getLogger('logstash')
logger.setLevel(logging.INFO)
logstash_handler = logging.FileHandler('logstash.log')
logstash_handler.setFormatter(LogstashFormatterV1())
logger.addHandler(logstash_handler)

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@db:5432/mydatabase'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
jwt = JWTManager(app)
db.init_app(app)

with app.app_context():
    db.create_all()

def verificar_existencia_usuario_y_correo(user_name, email=None):
    # Verificar si el usuario ya existe
    usuario_existente = Usuario.query.filter_by(user_name=user_name).first()
    if usuario_existente:
        return {"error": "El nombre de usuario ya existe en la base de datos."}, 409

    # Verificar si el correo ya existe si es apostador
    if email:
        correo_existente = Usuario.query.filter_by(email=email).first()
        if correo_existente:
            return {"error": "El correo electrónico ya existe en la base de datos."}, 409

    return None

# Login route to get a token
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    user = Usuario.query.filter_by(user_name=username).first()
    if user and user.password == password:
        access_token = create_access_token(identity={"username": username})
        return jsonify(access_token=access_token)
    return jsonify({"msg": "Bad username or password"}), 401

@app.route('/signUp', methods=['POST'])
def signUp():
        
        # Verificar existencia de usuario y correo
        error = verificar_existencia_usuario_y_correo(
            request.json["username"], 
            request.json["email"] 
        )
        if error:
            return error

        # Crear el nuevo usuario
        nuevo_usuario = Usuario(
            user_name=request.json["username"], 
            password=request.json["password"],
            email=request.json["email"],
        )
    
        try:
            # Iniciar la transacción
            db.session.add(nuevo_usuario)
            db.session.commit()

            token_de_acceso = create_access_token(identity=nuevo_usuario.id)
            return {"mensaje": "Usuario creado exitosamente", "token": token_de_acceso, "id": nuevo_usuario.id}, 201

        except IntegrityError as e:
            db.session.rollback()
            if "usuario" in str(e.orig):
                return {"error": "El nombre de usuario ya existe en la base de datos."}, 409
            elif "correo" in str(e.orig):
                return {"error": "El correo electrónico ya existe en la base de datos."}, 409
            else:
                return {"error": "Error de integridad en la base de datos."}, 409
        except Exception as e:
            db.session.rollback()
            return {"error": f"Ha ocurrido un error: {str(e)}"}, 500

if __name__ == '__main__':
    app.run(port=9090)