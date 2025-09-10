from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from models import db, User
from config import Config
from auth import bp as auth_bp
from microgrid import bp as telemetry_bp
import bcrypt

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    JWTManager(app)

    @app.route("/")
    def home():
        return jsonify({"status": "ok", "service": "cybergrid-controller"})

    app.register_blueprint(auth_bp)
    app.register_blueprint(telemetry_bp)

    with app.app_context():
        db.create_all()
        # Bootstrap an admin if not exists
        if not User.query.filter_by(username="admin").first():
            pw = bcrypt.hashpw(b"admin123", bcrypt.gensalt())
            admin = User(username="admin", password_hash=pw, role="admin")
            db.session.add(admin)
            db.session.commit()

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
