from flask_restx import Resource, Namespace, fields
from flask import current_app
from datetime import datetime
from . import ns_auth
from app import api
import bcrypt


login_input = api.model('login_input', {
    'username': fields.String(required=True),
    'password': fields.String(required=True),
})

@ns_auth.route('/auth')
class Authorization(Resource):
    @ns_auth.expect(login_input)
    def post(self):
        db = current_app.db
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
