import os
from flask import Flask
from translation.models import db
from translation.routes import translation_bp

def create_app():
    app = Flask(__name__)

    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    db.init_app(app)
    app.register_blueprint(translation_bp)

    @app.cli.command("init-db")
    def init_db_command():
        """Creates the database tables for the translation service."""
        with app.app_context():
            db.create_all()
            print("Translation database tables created.")

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5002, debug=True)