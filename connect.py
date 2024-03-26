from pymongo import MongoClient
from datetime import datetime
import bcrypt


client = MongoClient('mongodb://192.168.56.1:27017')

#password = bcrypt.hashpw('secret'.encode('utf-8'), bcrypt.gensalt())

#client.expense_tracker.users.delete_one({'username': 'cate1'})

users = client.expense_tracker.users.find()
expenses = client.expense_tracker.expenses.find()
print(list(users))
print(list(expenses))
