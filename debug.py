#!/usr/bin/python

import logging

# Set up a log on stderr _before_ we do the import,
# because a lot of stuff happens at import time
handler = logging.StreamHandler()
handler.setFormatter(
    logging.Formatter('%(asctime)s:%(levelname)s:%(message)s'))
logging.getLogger('kb_api').addHandler(handler)
logging.getLogger('kb_api').setLevel(logging.DEBUG)

import kb_api.server

kb_api.server.app.run(debug=True)
