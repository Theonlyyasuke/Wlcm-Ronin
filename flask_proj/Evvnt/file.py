from flask import Flask, jsonify
from .extensions import db, migrate, jwt
from .auth.routes import bp as auth_bp
from .events.routes import bp as events_bp
from .bookings.routes import bp as bookings_bp
from .admin.routes import bp as admin_bp
from .config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    # register blueprints

    app.register_blueprint(auth_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(bookings_bp)
    app.register_blueprint(admin_bp)

    # basic error handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"msg": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Server error")
        return jsonify({"msg": "Server error"}), 500

    return app
