from werkzeug.wsgi import DispatcherMiddleware
from kb_api.api import app as apiserver
from kb_api.admin import app as adminserver
from kb_api.config import APIConfig as config
from kb_api.database import db
import flask
import jinja2
my_path = os.path.abspath(__file__)

class ConfigFileMiddleware:
    def __init__(self, application):
        self.__config = os.getenv('KB_API_CONFIG',
                                  os.path.abspath(os.path.join(my_path, '..')))
        self.__application = application

    def __call__(self, environ, start_response):
        environ['KB_API_CONFIG'] = self.__config
        return self.__application(environ, start_response)

# Use a dispatcher to run both the admin and the API
# in the same WSGI environment
dispatcher = DispatcherMiddleware(apiserver,
                                  { '/keys': adminserver })

application=dispatcher
