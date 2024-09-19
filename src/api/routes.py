"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required

api = Blueprint('api', __name__)
api.config["JWT_SECRET_KEY"] = "amanda_dias"
jwt = JWTManager(api)
# Allow CORS requests to this API
CORS(api)

data_base = [{
    "email": "amanda@example.com", 
    "password": "1234"
}]

@api.route('/login', methods=['POST'])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    es_correcto = False

    user = User.query.filter_by(email=email, password=password).first()

    for user in data_base:
        if user.get ("email") == email and user.get ("password") == password:
            es_correcto = True

    if not es_correcto:
            return jsonify({"msg": "Bad email or password"}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({ "token": access_token, "user_id": user.id })

@api.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    return jsonify({"id": user.id, "email": user.email }), 200

if __name__ == "__main__":
    api.run()