import os
os.environ['KB_API_CONFIG'] = os.path.join(os.path.dirname(__file__),
                                           'conf/kb-api.ini')

from kb_api import application
