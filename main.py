from flask import Flask, request, jsonify, abort, Response
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid
import re
import logging
import os
import binascii
import schedule
import time
import hmac
import requests
import pki
import datetime
import json

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = b'814ebb74c7918a74cd45e165ea9d0a3a81ba06e85b563dc4'
app.config['SECURITY_PASSWORD_SALT'] = 'some_arbitrary_super_secret_string'
# app.config['SHARED_SECRET_KEY'] = f'{binascii.hexlify(os.urandom(24))}'

limiter = Limiter(app=app, key_func=get_remote_address)

db = SQLAlchemy(app)

roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):    
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    fs_uniquifier = db.Column(db.String(255), unique=True)
    active = db.Column(db.Boolean())
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
    is_admin = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    description = db.Column(db.String(255))
    price = db.Column(db.Float)
    image_url = db.Column(db.String(255))

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# AUTHENTICATION

# print(binascii.hexlify(os.urandom(24)))
    
# PUBLIC KEY INFRASTRUCTURE
    
private_key, public_key = pki.generate_key_pair()
ca_private_key, ca_certificate = pki.create_ca()

allowed_clients = [('814ebb', 'bbe418')]
allowed_ips = ['127.0.0.1']

def client_check(client_username):
    files = os.listdir('clients')

    filenames = [os.path.splitext(file)[0] for file in files]

    client_exists = client_username in filenames

    return client_exists
    
def first_time_connection(client_username, client_password, ip):
    usr_verify = client_check(client_username)
    if usr_verify is None:
        return abort(403, 'Forbidden')
    else:
        client_file = f'clients/{client_username}.json'
        if not os.path.exists(client_file):
            return abort(404, 'Client not found')
        try:
            with open(client_file, 'r') as f:
                data = json.loads(f.read())
        except Exception as e:
            raise e

        if (hmac.compare_digest(data['ip_addr'], ip) and
            hmac.compare_digest(data['client_password'], client_password)):
            try:
                client_certificate = pki.issue_certificate(ca_private_key, ca_certificate, public_key)
                return client_certificate
            except Exception as e:
                raise e
        else:
            return abort(403, 'Forbidden')
    
@app.route('/certificate/generate', methods=['POST'])
@limiter.limit("10/minute")
def generate_certificate():
    print(request.get_json())
    request_ip = request.remote_addr
    json_data = request.get_json()
    if 'client_id' not in json_data or 'client_password' not in json_data:
        return 'Missing data in request', 400
    client_id = json_data.get('client_id')
    client_password = json_data.get('client_password')
    try:
        client_certificate = first_time_connection(client_id, client_password, request_ip)
        return client_certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8'), 200
    except Exception as e:
        return str(e), 500

@app.route('/certificate/validate', methods=['POST'])
@limiter.limit("10/minute")
def validate_certificate():
    request_ip = request.remote_addr
    certificate_pem = request.get_json().get('certificate')
    if not certificate_pem:
        abort(400, 'Missing certificate')
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'), default_backend())
    except ValueError:
        return 'Invalid certificate', 400
    try:
        is_valid = pki.verify_certificate(ca_certificate, certificate)
    except Exception as e:
        with open(f'/logs/{datetime.datetime.now}-validate_certificate-error.log', 'a') as f:
            f.writelines(f'Error verifying certificate: {str(e)}')
        return f'Error verifying certificate', 500
    if not is_valid:
        return 'Certificate is not valid', 400
    else:
        return 'Certificate is valid', 200
    
def check_client_certificate(certificate_pem, ca_certificate):
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'), default_backend())
    except ValueError:
        abort(400, 'Invalid certificate')
    try:
        is_valid = pki.verify_certificate(ca_certificate, certificate)
    except Exception as e:
        with open(f'/logs/{datetime.datetime.now}-check_client_certificate-error.log', 'a') as f:
            f.writelines(f'Error verifying certificate: {str(e)}')
        abort(500, f'Error verifying certificate')
    if datetime.datetime.now(datetime.timezone.utc) > certificate.not_valid_after_utc:
        abort(400, 'Certificate has expired')
    if not is_valid:
        abort(400, 'Certificate is not valid')
    else:
        return 'Certificate is valid'

# USERS

def user_logging(function_name, context, error):
    with open(f'/logs/user/{datetime.datetime.now()}-{function_name}-error.log', 'a') as f:
        f.writelines(f'{context}: {error}')

@app.route('/user', methods=['POST'])
@limiter.limit("10/minute")
def create_user():
    data = request.get_json()
    certificate_pem = data.get('certificate')
    certificate_check = check_client_certificate(certificate_pem, ca_certificate)
    if certificate_check != 'Certificate is valid':
        return jsonify({'message': certificate_check}), 400
    try:
        if 'email' not in data or 'password' not in data:
            abort(400, description="Missing email or password")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", data['email']):
            abort(400, description="Invalid email")
        user = user_datastore.create_user(email=data['email'], password=data['password'], fs_uniquifier=str(uuid.uuid4()))
        db.session.commit()
        return jsonify(user_id=user.id, fs_uniquifier=user.fs_uniquifier), 201
    except Exception as e:
        user_logging('create_user', 'Error creating user', str(e))
        return jsonify({'message': 'Error creating user'}), 400

@app.route('/user/<string:fs_uniquifier>', methods=['GET'])
@limiter.limit("10/minute")
def read_user(fs_uniquifier):
    data = request.get_json()
    certificate_pem = data.get('certificate')
    certificate_check = check_client_certificate(certificate_pem, ca_certificate)
    if certificate_check != 'Certificate is valid':
        return jsonify({'message': certificate_check}), 400
    try:
        user = User.query.filter_by(fs_uniquifier=fs_uniquifier).first()
        if user is None:
            abort(404, description="User not found")
        return jsonify(user_id=user.id, email=user.email, fs_uniquifier=user.fs_uniquifier)
    except Exception as e:
        user_logging('read_user', 'Error reading user', str(e))
        return jsonify({'message': 'Error reading user'}), 400

@app.route('/user/email/<string:email>', methods=['GET'])
@limiter.limit("10/minute")
def get_user_by_email(email):
    data = request.get_json()
    certificate_pem = data.get('certificate')
    certificate_check = check_client_certificate(certificate_pem, ca_certificate)
    if certificate_check != 'Certificate is valid':
        return jsonify({'message': certificate_check}), 400
    try:
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            abort(400, description="Invalid email")
        user = User.query.filter_by(email=email).first()
        if user is None:
            abort(404, description="User not found")
        return jsonify(user_id=user.id, fs_uniquifier=user.fs_uniquifier, email=user.email)
    except Exception as e:
        user_logging('get_user_by_email', 'Error getting user by email', str(e))
        return jsonify({'message': 'Error getting user by email'}), 400

@app.route('/user/<string:fs_uniquifier>', methods=['PUT'])
@limiter.limit("10/minute")
def update_user(fs_uniquifier):
    data = request.get_json()
    certificate_pem = data.get('certificate')
    certificate_check = check_client_certificate(certificate_pem, ca_certificate)
    if certificate_check != 'Certificate is valid':
        return jsonify({'message': certificate_check}), 400
    try:
        data = request.get_json()
        user = User.query.filter_by(fs_uniquifier=fs_uniquifier).first()
        if user is None:
            abort(404, description="User not found")
        if 'email' in data:
            if not re.match(r"[^@]+@[^@]+\.[^@]+", data['email']):
                abort(400, description="Invalid email")
            user.email = data['email']
        if 'password' in data:
            user.password = data['password']
        db.session.commit()
        return jsonify(user_id=user.id, email=user.email, fs_uniquifier=user.fs_uniquifier)
    except Exception as e:
        user_logging('update_user', 'Error updating user', str(e))
        return jsonify({'message': 'Error updating user'}), 400

@app.route('/user/<string:fs_uniquifier>', methods=['DELETE'])
@limiter.limit("10/minute")
def delete_user(fs_uniquifier):
    data = request.get_json()
    certificate_pem = data.get('certificate')
    certificate_check = check_client_certificate(certificate_pem, ca_certificate)
    if certificate_check != 'Certificate is valid':
        return jsonify({'message': certificate_check}), 400
    try:
        user = User.query.filter_by(fs_uniquifier=fs_uniquifier).first()
        if user is None:
            abort(404, description="User not found")
        db.session.delete(user)
        db.session.commit()
        return '', 204
    except Exception as e:
        user_logging('delete_user', 'Error deleting user', str(e))
        return jsonify({'message': 'Error deleting user:'}), 400

# PRODUCTS

def product_logging(function_name, context, error):
    with open(f'/logs/user/{datetime.datetime.now()}-{function_name}-error.log', 'a') as f:
        f.writelines(f'{context}: {error}')

@app.route('/product', methods=['POST'])
@limiter.limit("10/minute")
def create_product(): 
    data = request.get_json()
    certificate_pem = data.get('certificate')
    certificate_check = check_client_certificate(certificate_pem, ca_certificate)
    if certificate_check != 'Certificate is valid':
        return jsonify({'message': certificate_check}), 400
    try:
        data = request.get_json()
        new_product = Product(name=data['name'], description=data['description'], price=data['price'], image_url=data['image_url'])
        db.session.add(new_product)
        db.session.commit()
        return jsonify({'message': 'Product created'}), 201
    except Exception as e:
        product_logging('create_product', 'Error creating product', str(e))
        return jsonify({'message': 'Error creating product:'}), 400


@app.route('/product/<int:id>', methods=['GET'])
@limiter.limit("10/minute")
def read_product(id): 
    data = request.get_json()
    certificate_pem = data.get('certificate')
    certificate_check = check_client_certificate(certificate_pem, ca_certificate)
    if certificate_check != 'Certificate is valid':
        return jsonify({'message': certificate_check}), 400
    product = Product.query.get_or_404(id)
    return jsonify({'name': product.name, 'description': product.description, 'price': product.price, 'image_url': product.image_url})

@app.route('/products', methods=['GET'])
@limiter.limit("10/minute")
def read_all_products():
    data = request.get_json()
    certificate_pem = data.get('certificate')
    # Check the client's certificate
    certificate_check = check_client_certificate(certificate_pem, ca_certificate)
    if certificate_check != 'Certificate is valid':
        return jsonify({'message': certificate_check}), 400
    products = Product.query.all()
    return jsonify([{'id': product.id, 'name': product.name, 'description': product.description, 'price': product.price, 'image_url': product.image_url} for product in products])

@app.route('/product/<int:id>', methods=['PUT'])
@limiter.limit("10/minute")
def update_product(id): 
    data = request.get_json()
    certificate_pem = data.get('certificate')
    certificate_check = check_client_certificate(certificate_pem, ca_certificate)
    if certificate_check != 'Certificate is valid':
        return jsonify({'message': certificate_check}), 400
    try:
        data = request.get_json()
        product = Product.query.get_or_404(id)
        product.name = data['name']
        product.description = data['description']
        product.price = data['price']
        product.image_url = data['image_url']  # Update image URL
        db.session.commit()
        return jsonify({'message': 'Product updated'})
    except Exception as e:
        product_logging('update_product', 'Error updating product', str(e))
        return jsonify({'message': 'Error updating product:'}), 400

@app.route('/product/<int:id>', methods=['DELETE'])
@limiter.limit("10/minute")
def delete_product(id): 
    data = request.get_json()
    certificate_pem = data.get('certificate')
    certificate_check = check_client_certificate(certificate_pem, ca_certificate)
    if certificate_check != 'Certificate is valid':
        return jsonify({'message': certificate_check}), 400
    try:
        product = Product.query.get_or_404(id)
        db.session.delete(product)
        db.session.commit()
        return jsonify({'message': 'Product deleted'})
    except Exception as e:
        product_logging('delete_product', 'Error deleting product', str(e))
        return jsonify({'message': 'Error deleting product:'}), 400

# ADMIN OPERATIONS

@app.route('/user/<string:fs_uniquifier>/is_admin', methods=['GET'])
@limiter.limit("10/minute")
def is_user_admin(fs_uniquifier):
    data = request.get_json()
    certificate_pem = data.get('certificate')
    certificate_check = check_client_certificate(certificate_pem, ca_certificate)
    if certificate_check != 'Certificate is valid':
        return jsonify({'message': certificate_check}), 400
    try:
        user = User.query.filter_by(fs_uniquifier=fs_uniquifier).first()
        if user is None:
            abort(404, description="User not found")
        return jsonify(is_admin=user.is_admin)
    except Exception as e:
        user_logging('is_user_admin', 'Error checking if user is admin', str(e))
        return jsonify({'message': 'Error checking if user is admin:'}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')

    with app.app_context():
        db.drop_all()
        db.create_all()