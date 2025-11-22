from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from auth.encryption import cipher

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # Encrypted username in DB
    username_encrypted = db.Column(db.LargeBinary, unique=True, nullable=False)

    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    @property
    def username(self):
        return cipher.decrypt(self.username_encrypted).decode()

    @username.setter
    def username(self, value):
        self.username_encrypted = cipher.encrypt(value.encode())

    def __init__(self, username, password, is_admin=False):
        self.username = username
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.is_admin = is_admin

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)