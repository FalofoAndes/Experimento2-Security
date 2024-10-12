from flask_sqlalchemy import SQLAlchemy
from marshmallow import fields, Schema
from marshmallow.fields import Decimal
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from decimal import Decimal
import enum

db = SQLAlchemy()

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50))
