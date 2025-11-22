from flask_sqlalchemy import SQLAlchemy
import datetime
from translation.encryption import cipher

db = SQLAlchemy()

class Translation(db.Model):
    __tablename__ = 'translations'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    user_id = db.Column(db.String(128), nullable=False, index=True)

    # Encrypted at rest
    source_text_encrypted = db.Column(db.LargeBinary, nullable=False)
    translated_text_encrypted = db.Column(db.LargeBinary, nullable=False)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    @property
    def source_text(self):
        return cipher.decrypt(self.source_text_encrypted).decode()

    @source_text.setter
    def source_text(self, value):
        self.source_text_encrypted = cipher.encrypt(value.encode())

    @property
    def translated_text(self):
        return cipher.decrypt(self.translated_text_encrypted).decode()

    @translated_text.setter
    def translated_text(self, value):
        self.translated_text_encrypted = cipher.encrypt(value.encode())

    def __init__(self, user_id, source_text, translated_text):
        self.user_id = user_id
        self.source_text = source_text
        self.translated_text = translated_text
