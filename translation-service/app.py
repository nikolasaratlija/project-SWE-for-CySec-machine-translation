import os
from flask import Flask
from translation.models import db
from translation.routes import translation_bp

def create_app(config_overrides=None):
    app = Flask(__name__)

    # Set default configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    
    # Apply overrides if they are passed in
    if config_overrides:
        app.config.update(config_overrides)

    # Initialize extensions
    db.init_app(app)
    
    # Register blueprints
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