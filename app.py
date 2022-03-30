import datetime
from db_config import DB_CONFIG
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from flask import abort
import jwt

SECRET_KEY = "b'|\xe7\xbfU3`\xc4\xec\xa7\xa9zf:}\xb5\xc7\xb9\x139^3@Dv'"
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_CONFIG
CORS(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)

from model.user import User, user_schema


def create_token(user_id):
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=4),
        'iat': datetime.datetime.utcnow(),
        'sub': user_id
    }
    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm='HS256'
    )


def extract_auth_token(authenticated_request):
    auth_header = authenticated_request.headers.get('Authorization')
    if auth_header:
        try:
            return auth_header.split(" ")[1]
        except IndexError:
            return None

    else:
        return None


def decode_token(token):
    payload = jwt.decode(token, SECRET_KEY, 'HS256')
    return payload['sub']


@app.route('/hello', methods=['GET'])
def hello_world():
    return "Hello World!"


@app.route("/signUp", methods=["POST"])
def signUp():
    username = request.json["user_name"]
    password = request.json["password"]
    newUser = User(username, password)
    db.session.add(newUser)
    db.session.commit()
    return jsonify(user_schema.dump(newUser))


@app.route("/authentication", methods=["POST"])
def auth():
    username = request.json["user_name"]
    password = request.json["password"]
    if not username and not password:
        abort(400)

    user = User.query.filter_by(user_name=username).first()

    if user is None:
        abort(403)

    passMatch = bcrypt.check_password_hash(user.hashed_password, password)

    if not passMatch:
        abort(403)

    tok = create_token(user.id)
    return jsonify(token=tok)

