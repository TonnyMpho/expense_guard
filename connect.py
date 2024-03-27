""" file for testing my database """
from pymongo import MongoClient


client = MongoClient('mongodb://192.168.56.1:27017')

users = client.expense_tracker.users.find()
expenses = client.expense_tracker.expenses.find()
print(list(users))
print(list(expenses))
