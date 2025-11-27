import os
from flask import Flask, request
from gateway.routes import gateway_bp
from logging.config import dictConfig
from pythonjsonlogger import jsonlogger

dictConfig({
    'version': 1,
    'formatters': {'json': {
        'class': 'pythonjsonlogger.jsonlogger.JsonFormatter',
        'format': '%(asctime)s %(name)s %(levelname)s %(message)s %(module)s %(lineno)d'
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'json'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})


def create_app():
    """Create and configure an instance of the Flask application."""
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

    # Load configuration from environment variables into the app's config
    app.config.from_mapping(
        AUTH_SERVICE_URL=os.environ.get('AUTH_SERVICE_URL'),
        TRANSLATION_SERVICE_URL=os.environ.get('TRANSLATION_SERVICE_URL')
    )

    app.register_blueprint(gateway_bp)
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)