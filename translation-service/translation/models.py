from flask_sqlalchemy import SQLAlchemy
import datetime

db = SQLAlchemy()

class Translation(db.Model):
    __tablename__ = 'translations'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # This ID comes from the auth service, but there's no database-level foreign key
    user_id = db.Column(db.String(128), nullable=False, index=True)
    source_text = db.Column(db.Text, nullable=False)
    translated_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __init__(self, user_id, source_text, translated_text):
        self.user_id = user_id
        self.source_text = source_text
        self.translated_text = translated_text