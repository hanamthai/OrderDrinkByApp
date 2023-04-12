# OrderDrinkByApp :tropical_drink:
## 1. Introduction
### :memo: Project name: Order drink by app mobile
### :dart: Goals: This application can help customers order drinks without leaving the house and it also helps store owners increase sales by selling online.

## 2. Installation Guide: :file_folder:
- Step 1: Clone this project in local computer
- Step 2: Download library you need to run this project by vitual eviroment ([Click here](https://github.com/hanamthai/manage-package-versions-in-python))
- Step 3: Create Database in Postgresql (I using pgAdmin4) by import file backup.sql ([Click here](https://www.youtube.com/watch?v=JFxY2qajjwA))

## 3. Usage Guide: :book: 
- Step 1: Set up environment variable: Create file ".env" based on .env.example
- Step 2: To run project, you can write this command in cmd:
```bash
python run.py
```

## 4. Key Features:
## :heavy_check_mark: I divided it into 3 routes
### :couple: General route: Users do not need to login are still able to use
- Login (using JWTs)
- Logout
- Register
- Show all drink
- Show drink detail
- Reset password by email
### :boy: Users route: Feature of users
- Show user information
- Change user information
- Change password
- Create order
- Cancel order
- Complete order
- Show order history (order status are 'Completed' and 'Cancelled')
- Show order current (order status are 'Preparing' and 'Delivering')
### :boy: Admins route: Feature of admins
- Show all user information
- Lock and unlock user account
- Create drink
- Delete drink (soft delete)
- Change drink infomation
- Update order status to 'Delivering'
- Cancel order (if this drink sold out)
- Show all order history (order status are 'Completed' and 'Cancelled')
- Show all order current (order status are 'Preparing' and 'Delivering')
- Show revenue statistics by day, month or year

## 5. Technologies and Libraries Used: :books:
### Framework: Flask
- Because this project is small and the time to build this application is short. So between Flask and Django, I chose flask
- In addition, Flask has a simple and easy to understand structure, so I can learn and start using Flask more quickly and easily than Django
### Library:
- psycopg2: Python library that gives us the ability to access the PostgreSQL database from Python.
- flask-cors: support CORS (Cross-Origin Resource Sharing) handling in Flask applications. CORS is a security policy in web browsers to protect users from attacks from external resources.
- bcrypt: is a password encryption algorithm
- flask_jwt_extended: this is internet standard, it create token for user authentication
## 6. References:
- I started this project by the way to read [flask document official](https://flask.palletsprojects.com/en/2.2.x/)
- But when I scale this project, I have to refactor by watching [this video](https://www.youtube.com/watch?v=Wfx4YBzg16s&list=PL-osiE80TeTs4UjLw5MM6OjgkjFeUxCYH&index=12)
## 7. APIs documentation
- [Postman](https://documenter.getpostman.com/view/21836660/2s93CGTGtg)
