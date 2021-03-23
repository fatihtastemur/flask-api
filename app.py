from flask import Flask, jsonify, request, Blueprint
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from passlib.hash import pbkdf2_sha256 as sha256
from validate_email import validate_email
import os

# Flask Application
app = Flask(__name__)

# Api Versioning
v1 = Blueprint("version1", "version1")

# Rate Limit
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["10 per minute", "50 per hour"]
)

# App JWT Config
app.config['JWT_SECRET_KEY'] = 'FLASK API JWT SECRET KEY'
jwt = JWTManager(app)

# MongoClient
client = MongoClient("mongodb://localhost:27017/")
# database
db = client["dcapi"]
# collection
users = db["Users"]
products = db["Products"]


# Generate Password Hash
def generate_hash(password):
    return sha256.hash(password)


# Verify Password Hash
def verify_hash(password, hash_):
    return sha256.verify(password, hash_)


# Dashboard
@app.route('/', methods=['GET'])
@limiter.exempt
def home():
    return '''<h1>Flask API</h1>'''


# Login
@v1.route("/users/login", methods=["POST"])
@limiter.limit("30 per minute")
def login():
    try:
        if request.is_json:
            username = request.json["username"]
            password = request.json["password"]
        else:
            username = request.form["username"]
            password = request.form["password"]

        login_user = users.find_one({"username": username})
        if login_user:
            db_password = login_user['password'].encode('UTF-8')
            if verify_hash(password, db_password):
                access_token = create_access_token(identity=username)
                return jsonify(msg="Login Succeeded", access_token=access_token), 201
            else:
                return jsonify(msg="Invalid Password"), 401
        else:
            return jsonify(msg="Invalid Username"), 401
    except:
        return jsonify(msg="Login Failed"), 400


# Register
@v1.route("/users/register", methods=["POST"])
@limiter.exempt
def register():
    try:
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]

        check_user = users.find_one({"username": username})
        if check_user:
            return jsonify(msg="User Already Exist"), 409
        else:
            if validate_email(email):
                user_info = dict(username=username, password=generate_hash(password), email=email)
                users.insert_one(user_info)
                return jsonify(msg="User Added Successfully"), 201
            else:
                return jsonify(msg="Invalid Email Address"), 400
    except:
        return jsonify(msg="User Not Created"), 400


# Delete User
@v1.route("/users/<string:username>", methods=["DELETE"])
@limiter.limit("5 per minute")
@jwt_required()
def delete_user(username):
    try:
        result = users.delete_one({"username": username})
        if result.deleted_count > 0:
            return jsonify(msg="User Deleted Successfully"), 200
        else:
            return jsonify(msg="User Not Found"), 404
    except:
        return jsonify(msg="User Not Deleted"), 400


# Update User
@v1.route("/users/<string:username>", methods=["PUT"])
@limiter.limit("30 per minute")
@jwt_required()
def update_user(username):
    try:
        email = request.form["email"]

        if validate_email(email):
            filters = {'username': username}
            new_values = {"$set": {'email': email}}

            users.update_one(filters, new_values)
            return jsonify(msg="User Updated Successfully"), 200
        else:
            return jsonify(msg="Invalid Email Address"), 400
    except:
        return jsonify(msg="User Not Updated"), 400


# Get User
@v1.route("/users/<string:username>", methods=["GET"])
@limiter.limit("30 per minute")
@jwt_required()
def get_user_info(username):
    try:
        user_info = users.find_one({"username": username})

        if user_info:
            return jsonify(username=username, email=user_info['email']), 200
        else:
            return jsonify(msg="User Not Found"), 404
    except:
        return jsonify(msg="Bad Request"), 400


# Get Product
@v1.route("/products/<int:product_id>", methods=["GET"])
@limiter.limit("30 per minute")
@jwt_required()
def get_product(product_id):
    try:
        product_data = products.find_one({"product_id": product_id})

        if product_data:
            product = {
                'product_id': product_data['product_id'],
                'title': product_data['title'],
                'price': product_data['price'],
                'currency': product_data['currency'],
                'stock': product_data['stock'],
                'status': product_data['status']
            }

            result = {
                'product': product
            }

            return jsonify(result), 200
        else:
            return jsonify(msg="Product Not Found"), 404
    except:
        return jsonify(msg="Bad Request"), 400


# Add Product
@v1.route("/products/new", methods=["POST"])
@limiter.limit("30 per minute")
@jwt_required()
def add_product():
    try:
        product_id = int(request.form["product_id"])
        title = request.form["title"]
        price = float(request.form["price"])
        currency = request.form["currency"]
        stock = int(request.form["stock"])

        if request.form["status"] == 'true' or request.form["status"] == 'True':
            status = True
        else:
            status = False

        check_product = products.find_one({"product_id": int(product_id)})

        if check_product:
            return jsonify(msg="Product Already Exist"), 409
        else:
            product_data = dict(product_id=product_id, title=title, price=price,
                                currency=currency.upper(), stock=stock, status=status)
            products.insert_one(product_data)
            return jsonify(msg="Product Added Successfully"), 200
    except:
        return jsonify(msg="Product Not Added"), 400


# Update Product
@v1.route("/products/<int:product_id>", methods=["PUT"])
@limiter.limit("30 per minute")
@jwt_required()
def update_product(product_id):
    try:
        params = {}
        if 'title' in request.form:
            title_dict = {'title': request.form['title']}
            params.update(title_dict)

        if 'price' in request.form:
            price_dict = {'price': float(request.form['price'])}
            params.update(price_dict)

        if 'currency' in request.form:
            currency = request.form["currency"]
            currency_dict = {'currency': currency.upper()}
            params.update(currency_dict)

        if 'stock' in request.form:
            stock_dict = {'stock': int(request.form['stock'])}
            params.update(stock_dict)

        if 'status' in request.form:
            if request.form["status"] == 'true' or request.form["status"] == 'True':
                status = True
            else:
                status = False
            status_dict = {'status': status}
            params.update(status_dict)

        filters = {'product_id': product_id}
        new_values = {"$set": params}

        products.update_one(filters, new_values)
        return jsonify(msg="Product Updated Successfully"), 200
    except:
        return jsonify(msg="Product Not Updated"), 400


# Delete Product
@v1.route("/products/<int:product_id>", methods=["DELETE"])
@limiter.limit("5 per minute")
@jwt_required()
def delete_product(product_id):
    try:
        result = products.delete_one({"product_id": product_id})
        if result.deleted_count > 0:
            return jsonify(msg="Product Deleted Successfully"), 200
        else:
            return jsonify(msg="Product Not Found"), 404
    except:
        return jsonify(msg="Product Not Deleted"), 400


# Product List
@v1.route("/products/list", methods=["GET"])
@limiter.limit("30 per minute")
@jwt_required()
def get_product_list():
    try:
        params = {}
        status_dict = {}
        if 'status' in request.form:
            if request.form["status"] == 'true' or request.form["status"] == 'True':
                status_dict = {'status': True}
            elif request.form["status"] == '' or request.form["status"] is None:
                status_dict = {}
            else:
                status_dict = {'status': False}

        params.update(status_dict)
        product_data = products.find(params)
        if product_data:
            result = []
            for item in product_data:
                product = {
                    'product_id': item['product_id'],
                    'title': item['title'],
                    'price': item['price'],
                    'currency': item['currency'],
                    'stock': item['stock'],
                    'status': item['status']
                }

                result.append(product)
            return jsonify(result), 200
        else:
            return jsonify(msg="Products Not Found"), 404
    except:
        return jsonify(msg="Bad Request"), 400


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.register_blueprint(v1, url_prefix="/api/v1")
    app.run(host='0.0.0.0', port=port, debug=True)
