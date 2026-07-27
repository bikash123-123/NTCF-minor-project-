"""
Flask application entry point.
"""

from flask import Flask, jsonify
from flask_cors import CORS

from backend.config import Config

from backend.routes.auth_routes import auth_bp
from backend.routes.dashboard_routes import dashboard_bp
from backend.routes.detection_routes import detection_bp
from backend.routes.firewall_routes import firewall_bp
from backend.routes.threat_routes import threat_bp


def create_app():
    """
    Create and configure the Flask application.
    """

    app = Flask(__name__)

    app.config.from_object(Config)

    CORS(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(detection_bp)
    app.register_blueprint(firewall_bp)
    app.register_blueprint(threat_bp)

    @app.errorhandler(404)
    def not_found(error):
        return jsonify(
            {
                "error": "Resource not found"
            }
        ), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify(
            {
                "error": "Internal server error"
            }
        ), 500

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=Config.DEBUG)