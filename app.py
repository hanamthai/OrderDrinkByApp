# app.py
from flask import Flask, jsonify, request, session
import bcrypt
from flask_cors import CORS  # pip install -U flask-cors
from datetime import timedelta

import psycopg2  # pip install psycopg2
import psycopg2.extras

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'drinkorderbyapp'
jwt = JWTManager(app)

app.config['SECRET_KEY'] = 'drinkorderbyapp'
# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=60)
CORS(app)

# Local
# DB_HOST = "localhost"
# DB_NAME = "Drink Order"
# DB_USER = "postgres"
# DB_PASS = "123"


# Public
DB_HOST = "postgresql-hanamthai.alwaysdata.net"
DB_NAME = "hanamthai_drinkorder"
DB_USER = "hanamthai_admin"
DB_PASS = "021101054"

conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER,
                        password=DB_PASS, host=DB_HOST)


@app.route('/')
def home():
    # if 'fullname' in session:
    #     fullname = session['fullname']
    #     return jsonify({'message': 'You are already logged in', 'fullname': fullname})
    # else:
    #     resp = jsonify({'message': 'Unauthorized'})
    #     resp.status_code = 401
    #     return resp
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    sql = "SELECT * FROM drinks"
    cursor.execute(sql)
    row = cursor.fetchall()
    all_drinks = [{'drinkid': drink[0], 'drinkname': drink[1], 'drinkimage': drink[2],
                   'description': drink[3], 'category': drink[4], 'status': drink[5]} for drink in row]
    return jsonify(all_drinks)


# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.


@app.route('/login', methods=['POST'])
def login():
    _json = request.json
    # validate the received values
    if 'phonenumber' in _json.keys() and 'password' in _json.keys():
        _phonenumber = _json['phonenumber']
        _password = _json['password']
        # check user exists
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        sql = "SELECT * FROM users WHERE phonenumber = %s"
        sql_where = (_phonenumber,)

        cursor.execute(sql, sql_where)
        row = cursor.fetchone()
        if row:
            fullname = row['fullname']
            password_hash = row['password']
            if bcrypt.checkpw(_password.encode('utf-8'), password_hash.encode('utf-8')):
                session['fullname'] = fullname
                cursor.close()
                # create token
                access_token = create_access_token(identity=_phonenumber)
                return jsonify(access_token=access_token)
            else:
                resp = jsonify({'message': 'Bad Request - invalid password'})
                resp.status_code = 400
                return resp
        else:
            resp = jsonify({'message': 'Bad Request - invalid login name'})
            resp.status_code = 400
            return resp
    else:
        resp = jsonify({'message': 'Bad Request - missing input'})
        resp.status_code = 400
        return resp


@app.route('/register', methods=['POST'])
def register():
    _json = request.json
    _phonenumber = _json['phonenumber']
    _password = _json['password']
    _fullname = _json['fullname']
    _rolename = _json['rolename']
    _address = _json['address']

    # INSERT user
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    # check phonenumber already exists
    sql = "SELECT * FROM users WHERE phonenumber = %s"
    sql_where = (_phonenumber,)
    cursor.execute(sql, sql_where)
    row = cursor.fetchone()
    if row == None:
        # hash password to save into database (khi encode password để hash thì sau đó ta phải decode password để save cái decode password đó vào database)
        hashed = bcrypt.hashpw(_password.encode('utf-8'), bcrypt.gensalt())
        _password = hashed.decode('utf-8')
        print(_password)
        # insert recored
        sql = "INSERT INTO users(phonenumber,password,fullname,rolename,address) VALUES(%s,%s,%s,%s,%s)"
        sql_where = (_phonenumber, _password, _fullname,
                     _rolename, _address)
        cursor.execute(sql, sql_where)
        conn.commit()
        cursor.close()
        return jsonify({'message': 'You completed register!'})
    else:
        cursor.close()
        return jsonify({'message': 'You phone already exists!'})


@app.route('/logout', methods=['POST'])
def logout():
    if 'fullname' in session:
        session.pop('fullname', None)
    return jsonify({'message': 'You successfully logged out'})


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == "__main__":
    app.run()
