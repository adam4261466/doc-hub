from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

file_tags = db.Table('file_tags',
    db.Column('file_id', db.Integer, db.ForeignKey('files.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    signup_source = db.Column(db.String(100), nullable=True)
    ls_customer_portal_url = db.Column(db.String(500), nullable=True)
    subscription_cancelled_at = db.Column(db.DateTime, nullable=True)
    is_pilot = db.Column(db.Boolean, default=False, nullable=True)
    pilot_purchased_at = db.Column(db.DateTime, nullable=True)

    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    subscription_status = db.Column(db.String(20), default="inactive")
    subscription_expires_at = db.Column(db.DateTime, nullable=True)
    lemonsqueezy_subscription_id = db.Column(db.String(100), nullable=True)

    files = db.relationship('File', backref='user', lazy=True)
    folders = db.relationship('Folder', backref='user', lazy=True)
    tags = db.relationship('Tag', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
class FaissIndexStore(db.Model):
    __tablename__ = 'faiss_index_store'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, unique=True)
    index_data = db.Column(db.LargeBinary, nullable=True)
    metadata_json = db.Column(db.JSON, nullable=True)
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(),
                           onupdate=db.func.current_timestamp())

class BillingEvent(db.Model):
    __tablename__ = 'billing_events'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    event_type = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=True)
    currency = db.Column(db.String(10), nullable=True)
    ls_order_id = db.Column(db.String(100), nullable=True)
    ls_subscription_id = db.Column(db.String(100), nullable=True)
    raw_payload = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())


class UploadUsage(db.Model):
    __tablename__ = 'upload_usage'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    month_key = db.Column(db.String(7), nullable=False)
    upload_count = db.Column(db.Integer, default=0)
    __table_args__ = (db.UniqueConstraint('user_id', 'month_key'),)


class Folder(db.Model):
    __tablename__ = 'folders'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    files = db.relationship('File', backref='folder', lazy=True)
    children = db.relationship('Folder', backref=db.backref('parent', remote_side=[id]), lazy=True)


class Tag(db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    color = db.Column(db.String(7), default='#6366f1')
    __table_args__ = (db.UniqueConstraint('name', 'user_id'),)


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
    content = db.Column(db.LargeBinary, nullable=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=True)
    tags = db.relationship('Tag', secondary=file_tags, backref='files')
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
