from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    # Relationship to files
    files = db.relationship('File', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    path = db.Column(db.String(500), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    processed = db.Column(db.Boolean, default=False)
    file_metadata = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    chunks = db.relationship('Chunk', backref='file', lazy=True)

class Chunk(db.Model):
    __tablename__ = 'chunks'
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text, nullable=False)
    start_char = db.Column(db.Integer, default=0)
    end_char = db.Column(db.Integer, default=0)
    chunk_metadata = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class IndexMeta(db.Model):
    __tablename__ = 'index_meta'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    index_path = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
