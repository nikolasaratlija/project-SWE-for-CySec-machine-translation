import os
from flask import Flask
from auth.models import db, User
from auth.routes import auth_bp
from flask_jwt_extended import JWTManager

def create_app():
    app = Flask(__name__)

    # --- Configuration ---
    # Load environment variables from a .env file if it exists
    # In docker-compose, we set these variables directly.
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')

    # --- Extensions ---
    db.init_app(app)
    jwt = JWTManager(app)

    # --- Blueprints ---
    app.register_blueprint(auth_bp)

    # --- CLI Commands ---
    @app.cli.command("init-db")
    def init_db():
        """Creates database tables and seeds it with initial users."""
        with app.app_context():
            db.create_all()
            print("Database tables created.")

            users_to_add = [
                {'username': 'admin', 'password': 'admin_password', 'is_admin': True},
                {'username': 'Nikola', 'password': 'password123'},
                {'username': 'Debora', 'password': 'password123'},
                {'username': 'Guido', 'password': 'password123'},
                {'username': 'Amreesh', 'password': 'password123'}
            ]

            for user_data in users_to_add:
                if not User.query.filter_by(username=user_data['username']).first():
                    user = User(
                        username=user_data['username'],
                        password=user_data['password'],
                        is_admin=user_data.get('is_admin', False)
                    )
                    db.session.add(user)
                    print(f"User '{user_data['username']}' created.")

            db.session.commit()
            print("Initial users have been seeded.")

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5001, debug=True)