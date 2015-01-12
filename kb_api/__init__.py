import logging
import flask
import jinja2

logging.getLogger('kb_api').addHandler(logging.NullHandler())

from .admin import admin_blueprint
from .api import api_blueprint
from .config import APIConfig as config
from .database import db

_app = flask.Flask(__name__)

static = flask.Blueprint('static', 'static', static_folder='static')

_app.register_blueprint(static)
_app.register_blueprint(admin_blueprint, url_prefix='/keys')
_app.register_blueprint(api_blueprint, url_prefix='/api/v1')
_app.config['SQLALCHEMY_DATABASE_URI'] = config.get('Authentication', 'db_uri')
_app.secret_key = config.get('App', 'secret_key')
db.init_app(_app)
_app.jinja_env.undefined = jinja2.StrictUndefined

application = _app
