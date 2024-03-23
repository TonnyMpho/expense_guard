from flask import Flask, request, jsonify, abort
from pymongo import MongoClient
from bson import ObjectId
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
import json


app = Flask(__name__)
app.config['SECRET_KEY'] = '7eed3b8d-b4a8-4aa5-bc9c-dc0eea04ac33' # used uuid
app.config["JWT_SECRET_KEY"] = '7eed3b8d-b4a8-4aa5-bc9c-dc0eea04ac33'
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
jwt = JWTManager(app)


mongo = MongoClient("mongodb://192.168.56.1:27017")


@app.route('/api/v1/login', methods=['POST'], strict_slashes=False)
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    try:
        user = mongo.expense_tracker.users.find_one({'username': username})
        if user:
            hashed_password = user.get('password')
            user_id = str(user.get('_id'))
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                access_token = create_access_token(identity=user_id)
                return jsonify({'access_token': access_token}), 200
            else:
                return jsonify({'message': 'Invalid username or password'}), 401
        else:
            return jsonify({'message': 'Invalid username or password'}), 401
    except Exception as e:
        return jsonify({'message': 'Invalid username or password'}), 401


@app.route('/api/v1/users', methods=["GET"], strict_slashes=False)
@jwt_required()
def users():
    current_user = get_jwt_identity()
    users = mongo.expense_tracker.users.find()
    users = [user for user in users]

    for user in users:
        user['_id'] = str(user['_id'])
        user['password'] = str(user['password'])
    return jsonify(users), 200


@app.route("/api/v1/users/<user_id>", methods=["GET"], strict_slashes=False)
@jwt_required()
def user(user_id):
    current_user = get_jwt_identity()
    user = mongo.expense_tracker.users.find_one({ "_id": ObjectId(user_id) })
    if user:
        user['_id'] = str(user['_id'])
        user['password'] = str(user['password'])
        return jsonify(user), 200
    else:
        return jsonify({ "error": "User not found" }), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
