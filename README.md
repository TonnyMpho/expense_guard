## Expense Tracker API

The Expense Tracker API is a RESTful web service designed to help users manage their finances efficiently. It allows users to register, log in, add expenses, view their expenses, and more. This README provides information on how to set up and use the Expense Tracker API.

### Features

- User registration and authentication using JWT tokens.
- CRUD operations for managing expenses.
- Secure password hashing using bcrypt.
- Rate limiting to prevent abuse and ensure system stability.
- Integration with MongoDB for data storage.

### Technologies Used

- Flask: A micro web framework for building APIs in Python.
- MongoDB: A NoSQL database used for storing user and expense data.
- Flask-JWT-Extended: For user authentication and authorization using JSON Web Tokens (JWT).
- bcrypt: A library for hashing passwords securely.
- Flask-RESTX: An extension for Flask that simplifies API development and documentation.

### Setup Instructions

1. Clone the repository to your local machine:

```
git clone https://github.com/TonnyMpho/expense_guard.git
```

2. Navigate to the project directory:
```
cd expense_guard
```

3. Install the required dependencies using pip:
```
pip install -r requirements.txt
```

4. Set up a MongoDB instance either locally or using a cloud service. Update the MongoDB connection URI in the __app.py__ file.

5. Run the Flask application:
```
python3 api/v1/app.py
```
6. The Expense Tracker API should now be running locally at http://localhost:5000.

### Usage

- To register a new user, send a POST request to __/api/v1/users__ with the user's details in the request body.
- To log in, send a POST request to __/api/v1/login__ with the user's credentials in the request body. You will receive a JWT token upon successful authentication.
- Use the JWT token to access protected endpoints, such as adding expenses or viewing user details.

### Contributing

Contributions are welcome! If you have any suggestions, improvements, or feature requests, please open an issue or submit a pull request.

### License

This project is licensed under the [MIT License](https://mit-license.org/).
