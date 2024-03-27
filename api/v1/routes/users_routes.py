from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restx import Resource, fields
from flask import current_app
from bson import ObjectId
from datetime import datetime
import bcrypt
from . import ns_users
from app import api

def validate_user(data):
    required = ['username', 'email', 'password']
    for field in required:
        if field not in data:
            return False
    return True


user_model = api.model('user_model', {
    'username': fields.String(reqiured=True),
    'email': fields.String(required=True),
    'password': fields.String(required=True),
})

user_output = api.model('user_output', {
    '_id': fields.String,
    'username': fields.String,
    'email': fields.String,
    'created_at': fields.DateTime,
})


@ns_users.route('/users')
class Users(Resource):

    @ns_users.doc(security='JWT-token')
    @ns_users.marshal_list_with(user_output)
    @jwt_required()
    def get(self):
        db = current_app.db
        user = get_jwt_identity()
        users = db.users.find()
        users = list(users)

        return users, 200

    @ns_users.expect(user_model)
    def post(self):
        db = current_app.db
        data = ns_users.payload
        if not validate_user(data):
            return {'error': 'Missing required fields'}, 400

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        created_at = datetime.now()

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            existing = db.users.find_one({'$or': [{'username': username, 'email': email}]})
            if existing:
                return {'error': 'Username or email already exists'}, 400

            user = {
                'username': username,
                'email': email,
                'password': hashed_password,
                'created_at': created_at
            }

            db.users.insert_one(user)
            return { 'message': 'User created successfully'}, 200
        except Exception as e:
            return {'error': str(e)}, 500


@ns_users.route("/users/<string:user_id>")
class User(Resource):
    @ns_users.doc(security='JWT-token')
    @jwt_required()
    @ns_users.marshal_with(user_output)
    @ns_users.doc(params={'user_id': 'User ID'})
    def get(self, user_id):
        db = current_app.db
        current_user = get_jwt_identity()
        try:
            user = db.users.find_one({ "_id": ObjectId(user_id) })
            if user:
                return user, 200
            else:
                return {"error": "User not found" }, 404
        except Exception as e:
            return {'error': str(e)}, 404

