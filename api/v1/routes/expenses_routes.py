from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restx import Resource, fields
from flask import current_app
from bson import ObjectId
from datetime import datetime
from . import ns_expenses
from app import api


def validate_expense(data):
    required = ['decscription', 'amount', 'category', 'date']
    for field in required:
        if field not in data:
            return False
    return True


expense_model = api.model('expense_model', {
    'description': fields.String,
    'amount': fields.Float,
    'category': fields.String,
    'date': fields.DateTime,
})

expense_output = api.model('expense_output', {
    'user_id': fields.String,
    'description': fields.String,
    'amount': fields.Float,
    'category': fields.String,
    'date': fields.DateTime,
})


@ns_expenses.route("/expenses")
class Expenses(Resource):
    @ns_expenses.doc(security='JWT-token')
    @ns_expenses.expect(expense_model)
    @jwt_required()
    def post(self):
        data = ns_expenses.payload
        db = current_app.db
        if validate_expense(data):
            return {'error': 'Missing required fields'}, 400

        description = data.get('description')
        amount = data.get('amount')
        category = data.get('category')
        date = data.get('date')

        try:
            date = datetime.fromisoformat(date)
        except Exception as e:
            return {'error': str(e)}, 500
    
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
        db = current_app.db
        user_id = get_jwt_identity()

        try:
            expenses = db.expenses.find()
            expenses = list(expenses)

            return expenses, 200
        except Exception as e:
            return {'error': str(e)}, 500


@ns_expenses.route("/expenses/<string:expense_id>")
class Expense(Resource):
    @ns_expenses.expect(expense_model)
    @jwt_required()
    @ns_expenses.doc(security='JWT-token')
    def put(self, expense_id):
        db = current_app.db
        user = get_jwt_identity()

        data = request.json()
        description = data.get('description')
        amount = data.get('amount')
        category = request.get('category')
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
        db = current_app.db
        user = get_jwt_identity()

        deleted = db.expenses.delete_one({'_id': ObjectId(expense_id), 'user_id': ObjectId(user)})

        if deleted.deleted_count == 1:
            return {'message': 'Expense deleted successfuly'}, 200
        else:
            return {'error': 'Expense not found or failed to delete'}, 404


@ns_expenses.route("/expenses/filter")
class ExpenseFilter(Resource):
    @jwt_required()
    @ns_expenses.doc(security='JWT-token')
    @ns_expenses.marshal_list_with(expense_output)
    def get(self):
        db = current_app.db
        user_id = get_jwt_identity()
        filters = request.args.to_dict()

        try:
            expenses = db.expenses.find({'user_id': ObjectId(user_id), **filters})
            expenses = list(expenses)

            return expenses, 200
        except Exception:
            return {'error': str(e)}, 500

