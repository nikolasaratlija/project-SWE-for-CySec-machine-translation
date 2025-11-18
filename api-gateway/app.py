import os
from flask import Flask
from gateway.routes import gateway_bp

def create_app():
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__)

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