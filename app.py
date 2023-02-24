# "orderdrink_api_flask_env\Scripts\activate" to activate enviroments of packet
# "orderdrink_api_flask_env\Scripts\deactivate" to deactivate enviroments of packet
# app.py
from flask import Flask, jsonify, request, session
import bcrypt
from flask_cors import CORS  # pip install -U flask-cors
from datetime import timedelta

import psycopg2  # pip install psycopg2
import psycopg2.extras

from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import get_jwt

app = Flask(__name__)

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'drinkorderbyapp'
jwt = JWTManager(app)

app.config['SECRET_KEY'] = 'drinkorderbyapp'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=60)
CORS(app)

# Local
DB_HOST = "localhost"
DB_NAME = "Drink Order"
DB_USER = "postgres"
DB_PASS = "123"


# Public
# DB_HOST = "postgresql-hanamthai.alwaysdata.net"
# DB_NAME = "hanamthai_drinkorder"
# DB_USER = "hanamthai_admin"
# DB_PASS = "021101054"

conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER,
                        password=DB_PASS, host=DB_HOST)


@app.route('/drink')
def home():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # sql = "SELECT drinks.drinkid,drinkname,drinkimage,category,MIN(price),status FROM drinks INNER JOIN drinksize ON drinks.drinkid = drinksize.drinkid INNER JOIN sizes ON sizes.sizeid = drinksize.sizeid GROUP BY drinks.drinkid ORDER BY drinks.drinkid"
    sql = """
    SELECT
        drinks.drinkid, drinkname, drinkimage,
        categoryid, MIN(price), status
    FROM drinks
    INNER JOIN drinksize
        ON drinks.drinkid = drinksize.drinkid
    INNER JOIN sizes
        ON sizes.sizeid = drinksize.sizeid
    WHERE status = 'Available'
    GROUP BY drinks.drinkid
    ORDER BY drinks.drinkid
    """
    cursor.execute(sql)
    row = cursor.fetchall()
    cursor.close()
    drinks = [{'drinkid': drink[0], 'drinkname': drink[1], 'drinkimage': drink[2],
                'categoryid': drink[3],'price':drink[4] ,'status': drink[5]} for drink in row]
    return jsonify(drinks=drinks)


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
            password_hash = row['password']
            userid = row['userid']
            rolename = row['rolename']
            if bcrypt.checkpw(_password.encode('utf-8'), password_hash.encode('utf-8')):
                cursor.close()
                # create token
                additional_claims = {"rolename":rolename}
                access_token = create_access_token(identity=userid,additional_claims=additional_claims)
                session['access_token'] = access_token
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
        return jsonify({'message': 'Your phone already exists!'})


@app.route('/logout', methods=['POST'])
def logout():
    if 'access_token' in session:
        session.pop('access_token', None)
    return jsonify({'message': 'You successfully logged out'})


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    claims = get_jwt()
    _userid = claims['sub']
    _rolename = claims['rolename']
    return jsonify({"userid":_userid,"rolename":_rolename})


# drink detail
@app.route('/drink/<int:id>', methods=['GET'])
def drinkdetail(id):
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    sql = "SELECT * FROM drinks WHERE drinkid = %s"

    # Column contains topping's name and price of a drink
    sql_topping = "select t.toppingid,nametopping,price from drinks as d inner join drinktopping as dt on dt.drinkid = d.drinkid inner join toppings as t on t.toppingid = dt.toppingid where d.drinkid = %s"

    # # Column contains size's name and price of a drink
    sql_size = """ 
        select 
            s.sizeid,namesize,price from drinks as d
        inner join 
            drinksize as ds 
        on 
            ds.drinkid = d.drinkid
        inner join 
            sizes as s 
        on s.sizeid = ds.sizeid
        where d.drinkid = %s
        """

    sql_where = (id,)

    cursor.execute(sql, sql_where)
    drink = cursor.fetchone()

    cursor.execute(sql_topping,sql_where)
    topping = cursor.fetchall()

    cursor.execute(sql_size,sql_where)
    size = cursor.fetchall()

    _drink = {'drinkid': drink[0], 'drinkname': drink[1], 'drinkimage': drink[2],
                   'description': drink[3],'status': drink[4],'categoryid':drink[5]}
    _topping = [{"toppingid":i[0],"nametopping":i[1],"pricetopping":i[2]} for i in topping]
    _size = [{"sizeid":j[0],"namesize":j[1],"price":j[2]} for j in size]
    
    cursor.close()
    if drink:
        return jsonify(drink=_drink,topping=_topping,size=_size)
    else:
        return jsonify({'message':'Item not found!'})


# category info
@app.route('/drink/category', methods=['GET'])
def category_info():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    sql = """
    SELECT * FROM categories
    """
    cursor.execute(sql)
    row = cursor.fetchall()
    categories = [{'categoryid': category[0], 'categoryname': category[1]} for category in row]
    cursor.close()
    return jsonify(categories=categories)


# user infomation
@app.route('/userInfo', methods=['GET','PUT'])
@jwt_required()
def user_info():
    userid = get_jwt_identity()

    if request.method == 'GET':
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        sql = """
        SELECT * FROM users WHERE userid = %s
        """
        sql_where = (userid,)
        cursor.execute(sql,sql_where)
        row = cursor.fetchone()
        print(type(row))
        user = {'userid':row[0],'phonenumber':row[1],'password':row[2],'fullname':row[3],'rolename':row[4],'address':row[5]}
        return jsonify(user=user)
    
    elif request.method == 'PUT':
        _json = request.json
        _phonenumber = _json['phonenumber']
        _fullname = _json['fullname']
        _address = _json['address']

        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        sql = """
        UPDATE users 
        SET phonenumber = %s,
            fullname = %s,
            address = %s
        WHERE userid = %s
        """
        sql_where = (_phonenumber,_fullname,_address,userid)
        cursor.execute(sql,sql_where)
        conn.commit()
        cursor.close()
        return jsonify({"message":"User information updated!"})
    
    resp = jsonify({"message":"Error user information!"})
    resp.status_code = 501
    return resp
    

if __name__ == "__main__":
    app.run()
