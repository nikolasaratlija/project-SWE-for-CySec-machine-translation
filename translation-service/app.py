import os
from flask import Flask, request
from translation.models import db
from translation.routes import translation_bp
from logging.config import dictConfig


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


def create_app(config_overrides=None):
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