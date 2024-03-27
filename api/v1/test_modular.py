from flask import Flask
from flask_jwt_extended import JWTManager
from flask_restx import Api
from pymongo import MongoClient
from bson import ObjectId
from datetime import timedelta

from routes import ns_auth, ns_users, ns_expenses


app = Flask(__name__)
app.config['SECRET_KEY'] = '7eed3b8d-b4a8-4aa5-bc9c-dc0eea04ac33' # used uuid
app.config["JWT_SECRET_KEY"] = '7eed3b8d-b4a8-4aa5-bc9c-dc0eea04ac33'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)

jwt = JWTManager(app)
api = Api(app, version='1.0', title='API - Expense Guard',
        decription='API for expense tracker')

mongo = MongoClient("mongodb://192.168.56.1:27017")
db = mongo['expense_tracker']


api.add_namespace(ns_auth)
api.add_namespace(ns_users)
api.add_namespace(ns_expenses)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
