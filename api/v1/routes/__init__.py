from flask_restx import Namespace

authorizations = {
        'JWT-token': {
            'type': 'apiKey',
            'in': ['headers', 'cookies'],
            'name': 'Authorization'
        }
}

ns_auth = Namespace('api/v1', decription='Authorization')
ns_users = Namespace('api/v1', description='User registration and querying',
        authorizations=authorizations)
ns_expenses = Namespace('api/v1', description='Expenses', authorizations=authorizations)

from . import auth_route, users_routes, expenses_routes
