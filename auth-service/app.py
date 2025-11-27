import os
from flask import Flask, request
from flask_migrate import Migrate
from auth.models import db, User
from auth.routes import auth_bp
from logging.config import dictConfig
from flask_jwt_extended import JWTManager


dictConfig({
    'version': 1,
    'formatters': {
        'json': {
            'class': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s %(module)s %(lineno)d'
        }
    },
    'handlers': {
        'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://flask.logging.wsgi_errors_stream',
            'formatter': 'json'
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})


def create_app(test_config=None):
    app = Flask(__name__)

    @app.after_request
    def log_request_info(response):
        app.logger.info(
            "Request finished",
            extra={
                'remote_addr': request.remote_addr,
                'method': request.method,
                'path': request.path,
                'status_code': response.status_code,
                'content_length': response.content_length,
            }
        )
        return response

    # --- 1. Default Configuration ---
    # Load environment variables from a .env file if it exists
    # In docker-compose, we set these variables directly.
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL',
        'postgresql://user:password@localhost:5432/auth_db'
    )
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

    # --- 2. Apply Test Config (If present) ---
    # This overrides the defaults above BEFORE extensions load
    if test_config:
        app.config.update(test_config)

    # --- Extensions ---
    db.init_app(app)
    jwt = JWTManager(app)
    migrate = Migrate(app, db)

    # --- Blueprints ---
    app.register_blueprint(auth_bp)
    
    # --- CLI Commands ---
    @app.cli.command("init-db")
    def init_db():
        """Creates database tables and seeds it with initial users."""
        with app.app_context():
            print("Dropping all tables...")
            db.drop_all()

            db.create_all()
            print("Database tables created.")

            users_to_add = [
                {'username': 'admin', 'password': 'admin_password', 'is_admin': True},
                {'username': 'Nikola', 'password': 'password123'},
                {'username': 'Debora', 'password': 'password123', 'is_2fa_enabled': True, 'totp_secret': 'XA7FHV5BJOIOYEGP5E6DT2TEEBMGM65E'},
                {'username': 'Guido', 'password': 'password123'},
                {'username': 'Amreesh', 'password': 'password123'}
            ]

            for user_data in users_to_add:
                if not User.query.filter_by(username=user_data['username']).first():
                    user = User(
                        username=user_data['username'],
                        password=user_data['password'],
                        is_admin=user_data.get('is_admin', False),
                        totp_secret=user_data.get('totp_secret', None),
                        is_2fa_enabled=user_data.get('is_2fa_enabled', False)
                    )
                    db.session.add(user)
                    print(f"User '{user_data['username']}' created.")

            db.session.commit()
            print("Initial users have been seeded.")

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5001, debug=True)