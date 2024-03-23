from pymongo import MongoClient
from datetime import datetime
import bcrypt


client = MongoClient('mongodb://192.168.56.1:27017')

password = bcrypt.hashpw('secret'.encode('utf-8'), bcrypt.gensalt())

users = client.expense_tracker.users.find()
print(list(users))
