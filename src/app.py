
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, render_template, g
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_swagger_ui import get_swaggerui_blueprint
from flasgger import Swagger, swag_from
import jwt

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-key-min-32-chars!!!!!')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///notes.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_EXPIRATION_HOURS'] = 24

if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/notes_api.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Notes API startup')

CORS(app)

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs/"
}
swagger = Swagger(app, config=swagger_config)

SWAGGER_URL = '/api/docs'
API_URL = '/apispec.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Notes API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.relationship('Note', backref='author', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'notes_count': self.notes.count()
        }


class Note(db.Model):
    __tablename__ = 'notes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'user_id': self.user_id,
            'author': self.author.username if self.author else None
        }


with app.app_context():
    db.create_all()
    app.logger.info("Database tables created/verified")


def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=app.config['JWT_EXPIRATION_HOURS']),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


def decode_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

        if not token:
            app.logger.warning(f"Missing token for {request.endpoint}")
            return jsonify({'error': 'Token is missing', 'code': 'MISSING_TOKEN'}), 401

        payload = decode_token(token)
        if not payload:
            app.logger.warning(f"Invalid token for {request.endpoint}")
            return jsonify({'error': 'Token is invalid or expired', 'code': 'INVALID_TOKEN'}), 401

        user = User.query.get(payload['user_id'])
        if not user:
            app.logger.warning(f"User not found for token: {payload['user_id']}")
            return jsonify({'error': 'User not found', 'code': 'USER_NOT_FOUND'}), 401

        g.current_user = user
        return f(*args, **kwargs)

    return decorated


@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f'404 error: {error}')
    return jsonify({'error': 'Resource not found', 'code': 'NOT_FOUND'}), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'500 error: {error}')
    return jsonify({'error': 'Internal server error', 'code': 'SERVER_ERROR'}), 500


@app.errorhandler(400)
def bad_request_error(error):
    app.logger.warning(f'400 error: {error}')
    return jsonify({'error': 'Bad request', 'code': 'BAD_REQUEST'}), 400


@app.route('/api', methods=['GET'])
def api_root():
    return jsonify({
        'name': 'Notes API',
        'version': '2.0.0',
        'docs_url': '/api/docs',
        'endpoints': {
            'auth': ['POST /api/register', 'POST /api/login'],
            'notes': ['GET /api/notes', 'POST /api/notes', 'GET /api/notes/<id>', 'PUT /api/notes/<id>',
                      'DELETE /api/notes/<id>'],
            'user': ['GET /api/me']
        }
    })


@app.route('/api/register', methods=['POST'])
def register():
    print("\n" + "=" * 50)
    print("🔍 REGISTER DEBUG")
    print(f"Headers: {dict(request.headers)}")

    data = request.get_json()
    print(f"Received data: {data}")
    print("=" * 50 + "\n")

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    required_fields = ['username', 'email', 'password']
    missing_fields = [field for field in required_fields if field not in data]

    if missing_fields:
        app.logger.error(f"Missing fields: {missing_fields}")
        return jsonify({'error': f'Missing fields: {", ".join(missing_fields)}'}), 400

    if len(data['username']) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400

    if len(data['password']) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    if '@' not in data['email']:
        return jsonify({'error': 'Invalid email format'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400

    try:
        user = User(
            username=data['username'],
            email=data['email']
        )
        user.set_password(data['password'])

        db.session.add(user)
        db.session.commit()

        token = generate_token(user.id)
        app.logger.info(f"✅ New user registered: {user.username}")

        return jsonify({
            'message': 'User created successfully',
            'token': token,
            'user': user.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating user: {str(e)}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/api/login', methods=['POST'])
def login():

    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        app.logger.warning(f"Failed login attempt for {username}")
        return jsonify({'error': 'Invalid credentials'}), 401

    token = generate_token(user.id)
    app.logger.info(f"User logged in: {user.username}")

    return jsonify({
        'token': token,
        'user': user.to_dict()
    }), 200


@app.route('/api/me', methods=['GET'])
@token_required
def get_current_user():
    return jsonify({
        'user': g.current_user.to_dict()
    })


@app.route('/api/notes', methods=['GET'])
@token_required
def get_notes():

    query = Note.query.filter_by(user_id=g.current_user.id)

    search = request.args.get('search')
    title_filter = request.args.get('title')
    content_filter = request.args.get('content')

    if search:
        query = query.filter(
            db.or_(
                Note.title.contains(search),
                Note.content.contains(search)
            )
        )
        app.logger.info(f"User {g.current_user.id} searched for: {search}")

    if title_filter:
        query = query.filter(Note.title.contains(title_filter))

    if content_filter:
        query = query.filter(Note.content.contains(content_filter))

    sort_by = request.args.get('sort_by', 'created_at')
    sort_order = request.args.get('sort_order', 'desc')

    if sort_order == 'desc':
        query = query.order_by(getattr(Note, sort_by).desc())
    else:
        query = query.order_by(getattr(Note, sort_by).asc())

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    if per_page > 100:
        per_page = 100

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    result = {
        'items': [note.to_dict() for note in pagination.items],
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': pagination.pages,
        'has_prev': pagination.has_prev,
        'has_next': pagination.has_next
    }

    return jsonify(result), 200


@app.route('/api/notes', methods=['POST'])
@token_required
def create_note():

    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    title = data.get('title', '').strip()
    content = data.get('content', '').strip()

    if not title:
        return jsonify({'error': 'Title is required'}), 400

    if not content:
        return jsonify({'error': 'Content is required'}), 400

    note = Note(
        title=title,
        content=content,
        user_id=g.current_user.id
    )

    db.session.add(note)
    db.session.commit()

    app.logger.info(f"User {g.current_user.id} created note {note.id}")

    return jsonify(note.to_dict()), 201


@app.route('/api/notes/<int:note_id>', methods=['GET'])
@token_required
def get_note(note_id):

    note = Note.query.filter_by(id=note_id, user_id=g.current_user.id).first()

    if not note:
        return jsonify({'error': 'Note not found'}), 404

    return jsonify(note.to_dict()), 200


@app.route('/api/notes/<int:note_id>', methods=['PUT'])
@token_required
def update_note(note_id):

    note = Note.query.filter_by(id=note_id, user_id=g.current_user.id).first()

    if not note:
        return jsonify({'error': 'Note not found'}), 404

    data = request.get_json()

    if 'title' in data and data['title'].strip():
        note.title = data['title'].strip()

    if 'content' in data and data['content'].strip():
        note.content = data['content'].strip()

    db.session.commit()
    app.logger.info(f"User {g.current_user.id} updated note {note_id}")

    return jsonify(note.to_dict()), 200


@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@token_required
def delete_note(note_id):

    note = Note.query.filter_by(id=note_id, user_id=g.current_user.id).first()

    if not note:
        return jsonify({'error': 'Note not found'}), 404

    db.session.delete(note)
    db.session.commit()
    app.logger.info(f"User {g.current_user.id} deleted note {note_id}")

    return jsonify({'message': 'Note deleted successfully'}), 200


@app.route('/api/stats', methods=['GET'])
@token_required
def get_stats():

    total_notes = Note.query.filter_by(user_id=g.current_user.id).count()

    days_since_registration = (datetime.utcnow() - g.current_user.created_at).days or 1
    notes_per_day = round(total_notes / days_since_registration, 2)

    return jsonify({
        'total_notes': total_notes,
        'account_created': g.current_user.created_at.isoformat() if g.current_user.created_at else None,
        'notes_per_day': notes_per_day,
        'username': g.current_user.username
    }), 200


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login_page():
    return render_template('login.html')


@app.route('/register')
def register_page():
    return render_template('register.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)