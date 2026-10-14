"""Flask application construction without starting background threads."""

from copy import deepcopy
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask

from .configuration import apply_config_defaults, load_config
from .routes import web

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def create_app(config_data=None, config_path="config.yaml"):
    """Create an app with its own configuration and the existing UI assets."""
    load_dotenv(PROJECT_ROOT / ".env", override=False)
    app = Flask(
        "apachewatch",
        template_folder=str(PROJECT_ROOT / "templates"),
        static_folder=str(PROJECT_ROOT / "static"),
    )
    app.config["APACHEWATCH"] = (
        load_config(config_path) if config_data is None
        else apply_config_defaults(deepcopy(config_data))
    )
    app.register_blueprint(web)
    return app
