""" Expense tracker API """
from flask import Flask, request, jsonify, abort
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_restx import Api, Resource, Namespace, fields
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta
import bcrypt


app = Flask(__name__)
app.config['SECRET_KEY'] = '7eed3b8d-b4a8-4aa5-bc9c-dc0eea04ac33' # used uuid
app.config["JWT_SECRET_KEY"] = '7eed3b8d-b4a8-4aa5-bc9c-dc0eea04ac33'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config['PROPAGATE_EXCEPTIONS'] = True

jwt = JWTManager(app)
api = Api(app, version='1.0', title='API - Expense Guard',
        decription='API for expense tracker')

mongo = MongoClient("mongodb://127.0.0.1:27017")
db = mongo['expense_tracker']


def validate_user(data):
    """ method for validating user input """
    required = ['username', 'email', 'password']
    for field in required:
        if field not in data:
            return False
    return True

def validate_expense(data):
    """ method for validating expense input """
    required = ['description', 'amount', 'category', 'date']
    for field in required:
        if field not in data:
            return False
    return True

# User model
user_model = api.model('User', {
    'username': fields.String(reqiured=True),
    'email': fields.String(required=True),
    'password': fields.String(required=True),
})

# what the user output should include
user_output = api.model('User_out', {
    '_id': fields.String,
    'username': fields.String,
    'email': fields.String,
    'created_at': fields.DateTime,
})

# Expense model
expense_model = api.model('Expense', {
    'description': fields.String,
    'amount': fields.Float,
    'category': fields.String,
    'date': fields.DateTime,
})

# what the output should include
expense_output = api.model('Expense_output', {
    '_id': fields.String,
    'user_id': fields.String,
    'description': fields.String,
    'amount': fields.Float,
    'category': fields.String,
    'date': fields.DateTime,
})

# Athorization for swagger documentation
authorizations = {
        'JWT-token': {
            'type': 'apiKey',
            'in': ['headers', 'cookies'],
            'name': 'Authorization'
        }
}

ns_auth = Namespace('api/v1', decription='Authorization')

# login input model
login_input = api.model('login_input', {
    'username': fields.String(required=True),
    'password': fields.String(required=True),
})
#@api.errorhandler(jwt_extended_exception.NoAuthorizationError)
#def handle_auth_error(e):
#    return {'message': str(e)}, 401


@ns_auth.route('/auth')
class Authorization(Resource):
    """ class for authorization """

    @ns_auth.expect(login_input)
    def post(self):
        """ route for authorization """

        data = ns_auth.payload
        username = data.get('username')
        password = data.get('password')

        try:
            user = db.users.find_one({'username': username})
            if user:
                hashed_password = user.get('password')
                user_id = str(user.get('_id'))
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                    access_token = create_access_token(identity=user_id)
                    return {'access_token': access_token}, 200
                else:
                    return {'message': 'Invalid username or password'}, 401
            else:
                return {'message': 'Invalid username or password'}, 401
        except Exception as e:
            return {'error': str(e)}, 500


ns_users = Namespace('api/v1', description='User registration and viewing', authorizations=authorizations)

@ns_users.route('/users')
class Users(Resource):
    """ class for users """

    @jwt_required()
    @ns_users.doc(security='JWT-token')
    @ns_users.marshal_list_with(user_output)
    def get(self):
        """ route for fecthing all users """

        user = get_jwt_identity()
        users = db.users.find()
        users = list(users)

        return users, 200

    @ns_users.expect(user_model)
    def post(self):
        """ route for inserting a new user """

        data = ns_users.payload
        if not validate_user(data):
            return {'error': 'Missing required fields'}, 400

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        created_at = datetime.now()

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            existing_user = db.users.find_one({'$or': [{'username': username, 'email': email}]})
            if existing_user:
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
    """ class user """

    @jwt_required()
    @ns_users.doc(security='JWT-token')
    @ns_users.marshal_with(user_output)
    @ns_users.doc(params={'user_id': 'User ID'})
    def get(self, user_id):
        """ route for querying/fetching a user based on an ID """

        current_user = get_jwt_identity()
        try:
            user = db.users.find_one({ "_id": ObjectId(user_id) })
            if user:
                return user, 200
            else:
                return {"error": "User not found" }, 404
        except Exception as e:
            return {'error': str(e)}, 404


    @jwt_required()
    @ns_users.doc(security='JWT-token')
    @ns_users.expect(user_model)
    @ns_users.doc(params={'user_id': 'User ID'})
    def put(self, user_id):
        """ route for updating a user """

        auth_user_id = get_jwt_identity()
        data = ns_users.payload
        if not validate_user(data):
            return {'error': 'Missing required fields'}, 400

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            updated = db.users.update_one({ "_id": ObjectId(user_id)},
                {'$set': {'username': username, 'email': email,
                    'password': hashed_password}}
                )
            if updated.modified_count == 1:
                return {'message': 'User updated successfully'}, 200
            else:
                return {"error": "User not found or failed to update" }, 404
        except Exception as e:
            return {'error': str(e)}, 404


    @jwt_required()
    @ns_users.doc(security='JWT-token')
    @ns_users.doc(params={'user_id': 'User ID'})
    def delete(self, user_id):
        """ route for deleting a user """
        auth_user_id = get_jwt_identity()
        try:
            deleted = db.users.delete_one({ "_id": ObjectId(user_id) })
            if deleted.deleted_count == 1:
                return {'message': 'User deleted successfully'}, 200
            else:
                return {"error": "User not found or failed to delete" }, 404
        except Exception as e:
            return {'error': str(e)}, 404


ns_expenses = Namespace('api/v1', description='Expenses', authorizations=authorizations)

@ns_expenses.route("/expenses")
class Expenses(Resource):
    """ Expenses class """

    @jwt_required()
    @ns_expenses.doc(security='JWT-token')
    @ns_expenses.expect(expense_model)
    def post(self):
        """ route for inserting an expense """

        data = ns_expenses.payload
        if not validate_expense(data):
            return {'error': 'Missing required fields'}, 400

        description = data.get('description')
        amount = data.get('amount')
        category = data.get('category')
        date = data.get('date')

    
        user_id = get_jwt_identity()
        expense = {
                'user_id': ObjectId(user_id),
                'description': description,
                'amount': amount,
                'category': category,
                'date': date,
                'created_at': datetime.now()
            }
        try:
            db.expenses.insert_one(expense)
            return { 'message': 'Expense added successfully' }, 200
        except Exception:
            return { 'error': str(e)}, 500


    @jwt_required()
    @ns_expenses.doc(security='JWT-token')
    @ns_expenses.marshal_list_with(expense_output)
    def get(self):
        """ route for fetching all expenses """

        user_id = get_jwt_identity()

        try:
            expenses = db.expenses.find()
            expenses = list(expenses)

            return expenses, 200
        except Exception as e:
            return {'error': str(e)}, 500


@ns_expenses.route("/expenses/<string:expense_id>")
class Expense(Resource):
    """ class expense """

    @jwt_required()
    @ns_expenses.expect(expense_model)
    @ns_expenses.doc(security='JWT-token')
    def put(self, expense_id):
        """ route for updating an expense """

        user = get_jwt_identity()

        data = ns_expenses.payload
        if not validate_expense(data):
            return {'error': 'Missing required fields'}, 400

        description = data.get('description')
        amount = data.get('amount')
        category = data.get('category')
        date = data.get('date')

        try:
            date = datetime.fromisoformat(date)
        except Exception as e:
            return { 'error': str(e) }, 500

        update = db.expenses.update_one(
                {'_id': ObjectId(expense_id), 'user_id': ObjectId(user)},
                {'$set': {'description': description, 'amount': amount,
                    'category':category, 'date': date}}
                )
        if update.modified_count == 1:
            return { 'message': 'Updated successfully' }, 200
        else:
            return {'error': 'expense not found or failed to update'}, 404


    @jwt_required()
    @ns_expenses.doc(security='JWT-token')
    def delete(self, expense_id):
        """ route for deleting an expense """

        user = get_jwt_identity()

        deleted = db.expenses.delete_one({'_id': ObjectId(expense_id), 'user_id': ObjectId(user)})

        if deleted.deleted_count == 1:
            return {'message': 'Expense deleted successfuly'}, 200
        else:
            return {'error': 'Expense not found or failed to delete'}, 404


    @jwt_required()
    @ns_expenses.doc(security='JWT-token')
    @ns_expenses.marshal_with(expense_output)
    def get(self, expense_id):
        """ route for fetching an expense """

        user_id = get_jwt_identity()
        try:
            expense = db.expenses.find_one({'_id': ObjectId(expense_id)})
            if expense:
                return expense, 200
            else:
                return {'error': 'Expense not found'}, 404
        except Exception as e:
            return {'error': str(e)}, 500


@ns_expenses.route("/expenses/filter")
class ExpenseFilter(Resource):
    """ Expense filter class """

    @jwt_required()
    @ns_expenses.doc(security='JWT-token')
    @ns_expenses.marshal_list_with(expense_output)
    def get(self):
        """ route for querying expenses based on a filter """

        user_id = get_jwt_identity()
        filters = request.args.to_dict()

        try:
            expenses = db.expenses.find({'user_id': ObjectId(user_id), **filters})
            expenses = list(expenses)

            return expenses, 200
        except Exception:
            return {'error': str(e)}, 500


@ns_expenses.route("/expenses/user/<string:user_id>")
class UserExpenses(Resource):
    """ class """

    @jwt_required()
    @ns_expenses.doc(security='JWT-token')
    @ns_expenses.doc(params={'user_id': 'User Id'})
    @ns_expenses.marshal_list_with(expense_output)
    def get(self, user_id):
        """ route for fetching expenses based on a User ID """
        user = get_jwt_identity()

        try:
            expenses = db.expenses.find({'user_id': ObjectId(user_id)})
            expenses = list(expenses)

            if expenses:
                return expenses, 200
            else:
                abort(404, 'User has no expenses')
        except Exception as e:
            abort(404, 'User has no expenses or no found')


api.add_namespace(ns_auth)
api.add_namespace(ns_users)
api.add_namespace(ns_expenses)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
