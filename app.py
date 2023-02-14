# app.py
from flask import Flask, jsonify, request, session
import bcrypt
from flask_cors import CORS  # pip install -U flask-cors
from datetime import timedelta

import psycopg2  # pip install psycopg2
import psycopg2.extras

app = Flask(__name__)

app.config['SECRET_KEY'] = 'drinkorderbyapp'

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)
CORS(app)

DB_HOST = "localhost"
DB_NAME = "Drink Order"
DB_USER = "postgres"
DB_PASS = "123"

conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER,
                        password=DB_PASS, host=DB_HOST)


@app.route('/')
def home():
    # passhash = generate_password_hash("123456")
    # print(passhash)
    if 'fullname' in session:
        fullname = session['fullname']
        return jsonify({'message': 'You are already logged in', 'fullname': fullname})
    else:
        resp = jsonify({'message': 'Unauthorized'})
        resp.status_code = 401
        return resp

# hashed = bcrypt.hashpw(_password.encode('utf-8'), bcrypt.gensalt())
# print(type(hashed))
# print(hashed)


@app.route('/login', methods=['POST'])
def login():
    _json = request.json
    # validate the received values
    if 'phonenumber' in _json.keys() and 'password' in _json.keys():
        _phonenumber = _json['phonenumber']
        _password = _json['password']
        # hashed = bcrypt.hashpw(_password.encode('utf-8'), bcrypt.gensalt())
        # print(hashed.decode("utf-8"))
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
                return jsonify({'message': 'You are logged in successfully'})
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


if __name__ == "__main__":
    app.run()
