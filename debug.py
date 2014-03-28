#!/usr/bin/python

import kb_api.server
import logging

debug_fmt = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
hdlr = logging.StreamHandler()
hdlr.setFormatter(debug_fmt)
logging.getLogger('kb_api').addHandler(hdlr)
logging.getLogger('kb_api').setLevel(logging.DEBUG)

kb_api.server.app.run(debug=True)
