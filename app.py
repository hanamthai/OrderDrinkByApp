# "orderdrink_api_flask_env\Scripts\activate" to activate enviroments of packet
# "orderdrink_api_flask_env\Scripts\deactivate" to deactivate enviroments of packet
# app.py
from flask import Flask, jsonify, request, session, url_for
import bcrypt
from flask_cors import CORS  # pip install -U flask-cors
from datetime import timedelta
from flask_mail import Mail,Message

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
app.config['JWT_TOKEN_LOCATION'] = 'headers'
jwt = JWTManager(app)

app.config['SECRET_KEY'] = 'drinkorderbyapp'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=60)
# send email setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'noname09092001@gmail.com'
app.config['MAIL_PASSWORD'] = 'ulbtjapttoblznip'
mail = Mail(app)

CORS(app)   # Cross-origin resource sharing

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
    resp = jsonify(drinks=drinks)
    resp.status_code = 200
    return resp


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
        print(row)
        cursor.close()
        if row:
            password_hash = row['password']
            userid = row['userid']
            rolename = row['rolename']
            status = row['status']
            if status == 'inactive':
                resp = jsonify({"message":"Locked - Your account is locked! You can contact with our employee to know reason!"})
                resp.status_code = 423
                return resp
            elif bcrypt.checkpw(_password.encode('utf-8'), password_hash.encode('utf-8')):
                # create token
                additional_claims = {"rolename":rolename}
                access_token = create_access_token(identity=userid,additional_claims=additional_claims)
                session['access_token'] = access_token
                resp = jsonify(access_token=access_token)
                resp.status_code = 200
                return resp
            else:
                resp = jsonify({'message': 'Bad Request - Wrong password!'})
                resp.status_code = 400
                return resp
        else:
            resp = jsonify({'message': 'Bad Request - Your phone does not exist in the system!'})
            resp.status_code = 400
            return resp
    else:
        resp = jsonify({'message': 'Bad Request - Missing input!'})
        resp.status_code = 400
        return resp


@app.route('/register', methods=['POST'])
def register():
    _json = request.json
    _phonenumber = _json['phonenumber']
    _password = _json['password']
    _fullname = _json['fullname']
    _address = _json['address']
    _email = _json['email']

    # INSERT user
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    # check phonenumber and email already exists
    sql = "SELECT * FROM users WHERE phonenumber = %s or email = %s"
    sql_where = (_phonenumber,_email)
    cursor.execute(sql, sql_where)
    row = cursor.fetchone()
    if row == None:
        # hash password to save into database (khi encode password để hash thì sau đó ta phải decode password để save cái decode password đó vào database)
        hashed = bcrypt.hashpw(_password.encode('utf-8'), bcrypt.gensalt())
        _password = hashed.decode('utf-8')
        # insert recored
        sql = "INSERT INTO users(phonenumber,password,fullname,rolename,address,email,status) VALUES(%s,%s,%s,%s,%s,%s,%s)"
        sql_where = (_phonenumber, _password, _fullname,
                     'user', _address,_email,'action')
        cursor.execute(sql, sql_where)
        conn.commit()
        cursor.close()
        resp = jsonify({'message': 'You completed register!'})
        resp.status_code = 200
        return resp
    else:
        cursor.close()
        resp = jsonify({'message': 'Bad Request - Your phone or email already exists!'})
        resp.status_code = 400
        return resp


@app.route('/logout', methods=['POST'])
def logout():
    if 'access_token' in session:
        session.pop('access_token', None)
    resp =  jsonify({'message': 'You successfully logged out'})
    resp.status_code = 200
    return resp


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    claims = get_jwt()
    _userid = claims['sub']
    _rolename = claims['rolename']
    resp = jsonify({"userid":_userid,"rolename":_rolename})
    resp.status_code = 200
    return resp


# drink detail
@app.route('/drink/<int:id>', methods=['GET'])
def drinkdetail(id):
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    sql_drink = "SELECT * FROM drinks WHERE drinkid = %s and status = 'Available'"

    # Column contains topping's name and price of a drink
    sql_topping = """
    select 
        t.toppingid,nametopping,price 
    from drinks as d 
    inner join 
        drinktopping as dt 
    on 
        dt.drinkid = d.drinkid 
    inner join 
        toppings as t 
    on 
        t.toppingid = dt.toppingid 
    where d.drinkid = %s
    """

    # Column contains size's name and price of a drink
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
    # drink
    cursor.execute(sql_drink, sql_where)
    drink = cursor.fetchone()
    if drink == None:
        resp = jsonify({'message':'Not Found - Item not found!'})
        resp.status_code = 404
        return resp
    _drink = {'drinkid': drink['drinkid'], 'drinkname': drink['drinkname'], 'drinkimage': drink['drinkimage'],
                   'description': drink['description'],'status': drink['status'],'categoryid':drink['categoryid']}
    # topping
    cursor.execute(sql_topping,sql_where)
    topping = cursor.fetchall()
    if topping != None:
        _topping = [{"toppingid": i['toppingid'], "nametopping": i['nametopping'], "price": i['price']} for i in topping]
    else:
        _topping = []
    # size
    cursor.execute(sql_size,sql_where)
    size = cursor.fetchall()
    if size != None:
        _size = [{"sizeid": j['sizeid'], "namesize": j['namesize'], "price": j['price']} for j in size]
    else:
        _size = []
    
    cursor.close()
    resp = jsonify(drink=_drink,topping=_topping,size=_size)
    resp.status_code = 200
    return resp
        


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
    if categories:
        resp = jsonify(categories=categories)
        resp.status_code = 200
        return resp
    else:
        resp = jsonify({'message':'Not Found!'})
        resp.status_code = 404
        return resp


# get user information and change user information
@app.route('/userInfo', methods=['GET','PUT'])
@jwt_required()
def user_info():
    userid = get_jwt_identity()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if request.method == 'GET':
        sql = """
        SELECT 
            userid,phonenumber,fullname,rolename,address,email 
        FROM users WHERE userid = %s
        """
        sql_where = (userid,)
        cursor.execute(sql,sql_where)
        row = cursor.fetchone()
        user = {'userid':row['userid'],'phonenumber':row['phonenumber'],
                'fullname':row['fullname'],'rolename':row['rolename'],
                'address':row['address'],'email':row['email']}
        cursor.close()
        if user:
            resp = jsonify(user=user)
            resp.status_code = 200
            return resp
        else:
            resp = jsonify({"message": "Not Found!"})
            resp.status_code = 404
            return resp
    
    elif request.method == 'PUT':
        _json = request.json
        _fullname = _json['fullname']
        _address = _json['address']

        sql = """
        UPDATE users 
        SET fullname = %s,
            address = %s
        WHERE userid = %s
        """
        sql_where = (_fullname,_address,userid)
        cursor.execute(sql,sql_where)
        conn.commit()
        cursor.close()
        resp = jsonify({"message":"User information updated!"})
        resp.status_code = 200
        return resp
    
    cursor.close()
    resp = jsonify({"message":"Not Implemented - Server doesn't undertand your request method"})
    resp.status_code = 501
    return resp
    

# add and change topping
@app.route('/admin/topping',methods=['POST','PUT'])
@jwt_required()
def addAndChangeTopping():
    info = get_jwt()
    rolename = info['rolename']
    if rolename == 'admin':
        if request.method == 'POST':
            _json = request.json
            _nametopping = _json['nametopping']
            _price = _json['price']

            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            sql = """
            INSERT INTO toppings(nametopping,price) VALUES(%s,%s)
            """
            sql_where = (_nametopping,_price)
            cursor.execute(sql,sql_where)
            conn.commit()
            cursor.close()
            resp = jsonify({"message":"Added topping!"})
            resp.status_code = 200
            return resp

        elif request.method == 'PUT':
            _json = request.json
            _toppingid = _json['toppingid']
            _nametopping = _json['nametopping']
            _price = _json['price']
            
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            sql = """
            UPDATE toppings
            SET nametopping = %s,
                price = %s
            WHERE toppingid = %s
            """
            sql_where = (_nametopping,_price,_toppingid)
            cursor.execute(sql,sql_where)
            conn.commit()
            cursor.close()
            resp = jsonify({"message":"Updated topping!"})
            resp.status_code = 200
            return resp 

    else:
        resp = jsonify({"message":"Unauthorized - You are not authorized!"})
        resp.status_code = 401
        return resp


# create order
@app.route('/order',methods = ['POST'])
@jwt_required()
def createOrder():
    userid = get_jwt_identity()

    _json = request.json
    _order = _json['order']
    _item = _json['item']
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        # create order and get orderid
        sql_create_order = """
        INSERT INTO 
            orders(userid,totalprice,address,phonenumber,note,status,orderdate)
        VALUES(%s,%s,%s,%s,%s,'Preparing',LOCALTIMESTAMP)
        RETURNING orderid
        """
        sql_where = (userid,_order['totalprice'],_order['address'],_order['phonenumber'],_order['note'])
        cursor.execute(sql_create_order,sql_where)
        row = cursor.fetchone()
        orderid = row[0]
        conn.commit()

        # add record to items table and get itemid
        # loop run, cause we have many item in a request
        lst_itemid = []
        for i in _item:
            # we have to handling add record to items and itemtopping table
            sql_add_item = """
            INSERT INTO
                items(drinkid,price,itemquantity,sizeid)
            VALUES(%s,%s,%s,%s)
            RETURNING itemid
            """
            sql_where = (i['drinkid'],i['price'],i['itemquantity'],i['sizeid'])
            cursor.execute(sql_add_item,sql_where)
            row = cursor.fetchone()
            conn.commit()
            itemid = row[0]
            lst_itemid.append(itemid)

            # insert data to itemtopping table
            for j in i['toppingid']:
                sql_add_itemtopping = """
                INSERT INTO
                    itemtopping(itemid,toppingid)
                VALUES(%s,%s)
                """
                sql_where = (itemid,j)
                cursor.execute(sql_add_itemtopping,sql_where)
                conn.commit()

        # insert data to itemorder
        for i in lst_itemid:
            sql_add_itemorder = """
            INSERT INTO itemorder(orderid,itemid)
            VALUES(%s,%s)
            """
            sql_where = (orderid,i)
            cursor.execute(sql_add_itemorder,sql_where)
            conn.commit()
        
        cursor.close()

        resp = jsonify({"message":"Completed order! Your order are preparing!!!"})
        resp.status_code = 200
        return resp
    except:
        resp = jsonify({"message":"Internal Server Error"})
        resp.status_code = 500
        return resp

# add and update size
@app.route('/admin/size', methods=['POST','PUT'])
@jwt_required()
def addAndUpdateSize():
    info = get_jwt()
    rolename = info['rolename']
    if rolename == 'admin':
        if request.method == 'POST':
            _json = request.json()
            _namesize = _json['namesize']
            _price = _json['price']

            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            sql_add_size = """
            INSERT INTO sizes(namesize,price)
            VALUES(%s,%s)
            """
            sql_where = (_namesize,_price)
            cursor.execute(sql_add_size,sql_where)
            conn.commit()
            cursor.close()
            resp = jsonify({"message":"Added size!"})
            resp.status_code = 200
            return resp
        
        elif request.method == 'PUT':
            _json = request.json()
            _sizeid = _json['sizeid']
            _namesize = _json['namesize']
            _price = _json['price']

            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            sql_update_size = """
            UPDATE sizes
            SET namesize = %s,
                price = %s
            WHERE sizeid = %s
            """
            sql_where = (_namesize,_price,_sizeid)
            cursor.execute(sql_update_size,sql_where)
            conn.commit()
            cursor.close()
            resp = jsonify({"message":"Updated size!"})
            resp.status_code = 200
            return resp
    else:
        resp = jsonify({"message":"Unauthorized - You are not authorized!"})
        resp.status_code = 401
        return resp



@app.route('/admin/order/update',methods=['PUT'])
@jwt_required()
def orderStatusUpdate():
    info = get_jwt()
    rolename = info['rolename']
    
    if rolename == 'admin':
        _json = request.json
        orderid = _json['orderid']

        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        sql = """
        UPDATE orders
        SET status = 'Delivering'
        WHERE orderid = %s
        """
        sql_where = (orderid,)
        cursor.execute(sql,sql_where)
        conn.commit()
        cursor.close()
        resp = jsonify({"message":"Updated order status to 'Delivering'!"})
        resp.status_code = 200
        return resp
    
    else:
        resp = jsonify({"message":"Unauthorized - You are not authorized!"})
        resp.status_code = 401
        return resp



@app.route('/order/update',methods=['PUT'])
@jwt_required()
def userConfirmCompletedOrder():
    _json = request.json
    orderid = _json['orderid']

    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    sql = """
    UPDATE orders
    SET status = 'Completed'
    WHERE orderid = %s
    """
    sql_where = (orderid,)
    cursor.execute(sql,sql_where)
    conn.commit()
    cursor.close()
    resp = jsonify({"message":"Updated order status to 'Completed'!"})
    resp.status_code = 200
    return resp


@app.route('/changePassword',methods=['PUT'])
@jwt_required()
def changePassword():
    userid = get_jwt_identity()

    _json = request.json
    _oldPassword = _json['oldpassword']
    _newPassword = _json['newpassword']
    # Confirm old password
    cursor = conn.cursor(cursor_factory= psycopg2.extras.DictCursor)
    sql_get_password = """
    SELECT password FROM users
    WHERE userid = %s
    """
    sql_where = (userid,)
    cursor.execute(sql_get_password,sql_where)
    row = cursor.fetchone()
    password_hash = row[0]
    if bcrypt.checkpw(_oldPassword.encode('utf-8'),password_hash.encode('utf-8')):
        # hash password
        hashed = bcrypt.hashpw(_newPassword.encode('utf-8'),bcrypt.gensalt())
        _newPassword = hashed.decode('utf-8')
        
        sql_change_password = """
        UPDATE users
        SET password = %s
        WHERE userid = %s
        """
        sql_where = (_newPassword,userid)
        cursor.execute(sql_change_password,sql_where)
        conn.commit()
        cursor.close()
        resp = jsonify({"message":"Your password changed !!!"})
        resp.status = 200
        return resp
    else:
        resp = jsonify({"message":"Bad Request - Your old password is wrong"})
        resp.status_code = 400
        return resp


@app.route('/resetPassword',methods = ['POST'])
def resetRequest():
    _json = request.json
    _email = _json['email']
    
    # check email request has contained in the database
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    sql_check_email = """
    SELECT userid FROM users
    WHERE email = %s
    """
    sql_where = (_email,)
    cursor.execute(sql_check_email,sql_where)
    row = cursor.fetchone()
    userid = row['userid']
    cursor.close()
    
    if userid:
        sendEmail(userid,_email)
        resp = jsonify({"message":"Hệ thống đã gửi cho bạn mail thông báo thay đổi mật khẩu. Hãy vào mail để kiểm tra!"})
        resp.status_code = 200
        return resp
    else:
        resp = jsonify({"message":"Not Found - Email doesn't exists in system!"})
        resp.status_code = 400
        return resp



def sendEmail(userid,_email):
    token = create_access_token(identity=userid,expires_delta=timedelta(minutes=5))
    msg = Message('YÊU CẦU ĐẶT LẠI MẬT KHẨU',recipients=[_email],sender='noreply@gmail.com')

    msg.body = f""" Để đặt lại mật khẩu trong ứng dụng đặt đồ uống. Hãy nhấn vào link dưới đây:
    {url_for("verifyTokenEmail",jwt=token,_external=True)}
    Nếu bạn không phải là người gửi yêu cầu đổi mật khẩu. Hãy bỏ qua mail thông báo này.
    """
    mail.send(msg)


#{{HOST}}/resetPassword/token?jwt=<Your token>
@app.route('/resetPassword/token',methods=['PUT','GET'])
@jwt_required(locations="query_string")
def verifyTokenEmail():
    userid = get_jwt_identity()
    if userid:
        # hash password '123'
        _password = '123'
        hashed = bcrypt.hashpw(_password.encode('utf-8'), bcrypt.gensalt())
        _password_hash = hashed.decode('utf-8')

        # update password into database
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        sql_change_password_default = """
        UPDATE users
        SET password = %s
        WHERE userid = %s
        """
        sql_where = (_password_hash,userid)
        cursor.execute(sql_change_password_default,sql_where)
        conn.commit()
        cursor.close()

        resp = jsonify({"message":"Your password changed to '123'!!!"})
        resp.status_code = 200
        return resp
    else:
        resp = jsonify({"message":"Not Found - Account doesn't exists"})
        resp.status_code = 404
        return resp





if __name__ == "__main__":
    app.run()
