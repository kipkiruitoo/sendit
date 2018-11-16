from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:root@localhost/api'

db = SQLAlchemy(app)

@app.route("/v1")
def hello():
    return jsonify({"about": "Welcome to sendit api"})

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
class Parcel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    source = db.Column(db.String(50))
    current_location = db.Column(db.String(50))
    destination = db.Column(db.String(50))
    status = db.Column(db.String(50))
    user_id = db.Column(db.Integer)


# function to check if the jwt tokens are valid and prefent unauthorized access to the api
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs ):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message': 'token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])

            current_user = User.query.filter_by(public_id=data['public_id']).first()

        except:
            return jsonify({'message': 'token is invalid'}), 401
        
        return f(current_user, *args,  **kwargs)

    return decorated

# user routes and respective functions
@app.route('/v1/user', methods=['GET'])
@token_required
# gets all users from the databse and returns a json object
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'you are not authorized'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        
        output.append(user_data)

    return jsonify({"users": output})

@app.route('/v1/user/<public_id>', methods=['GET'])
@token_required
# gets only one user from the database and puts his/her info in a json object

def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'you are not authorized'})


    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found'})


    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return jsonify({"user": user_data})

@app.route('/v1/user', methods=['POST'])
@token_required
# creates a new user in the databse
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'you are not authorized'})

    data  = request.get_json(force=True)
    
    hashed_password = generate_password_hash(data['password'])
    new_user = User(public_id = str(uuid.uuid4()), name=data['name'], password= hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user Created'})


# updates a user to admin status
@app.route('/v1/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'you are not authorized'})


    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found'})
    
    user.admin = True
    db.session.commit()



    return jsonify({'message': 'User is now an admin'})

@app.route('/v1/user/<public_id>', methods=['DELETE'])
@token_required
# deletes user from the database
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'you are not authorized'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found'})
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})
    

# start the parcel routes 
@app.route('/v1/parcel')
@token_required
# function for the admin to get all the parcels
def get_all_parcels(current_user):
    if not current_user.admin:
        return jsonify({'message': 'you are not authorized'})

    parcels = Parcel.query.all()

    output = []

    for parcel in parcels:
        parcel_data = {}
        parcel_data['public_id'] = parcel.public_id
        parcel_data['name'] = parcel.name
        parcel_data['source'] = parcel.source
        parcel_data['destination'] = parcel.destination
        parcel_data['status'] = parcel.status
        parcel_data['user_id'] = parcel.user_id
        
        output.append(parcel_data)

    return jsonify({"users": output})




@app.route('/v1/parcel', methods=['POST'])

def create_parcel(current_user):
    user = current_user.id
    data  = request.get_json(force=True)

    parcel = Parcel(public_id = str(uuid.uuid4()), name=data['name'], source=data['source'], destination=data['destination'], status='started', user_id=user)
    db.session.add(parcel)
    db.session.commit()

    return jsonify({'message': 'Parcel order created successfully'})

@app.route('/v1/parcel/<public_id>/destination', methods=['PUT'])
@token_required
def change_destination(current_user, public_id):
   

    parcel = Parcel.query.filter_by(public_id=public_id).first()
    if not parcel:
        return jsonify({'message': 'No Parcel found'})
    
    data  = request.get_json(force=True)
    parcel.destination = data['destination']
    db.session.commit()



    return jsonify({'message': 'Destination changed successully'})



@app.route('/v1/parcel/<public_id>', methods=['PUT'])
@token_required
def edit_parcel(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'you are not authorized'})


    parcel = Parcel.query.filter_by(public_id=public_id).first()
    if not parcel:
        return jsonify({'message': 'No Parcel found'})
    
    data  = request.get_json(force=True)
    parcel.status = data['status']
    parcel.current_location = data['current_location']
    db.session.commit()



    return jsonify({'message': 'Order Successfully edited'})

@app.route('/v1/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login Required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login Required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30) }, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login Required!"'})


  
if __name__ == '__main__':
    app.run(debug=True)
