#!/usr/bin/python

import logging
import os
import uuid
import socket

from OpenSSL import SSL
from werkzeug.serving import run_simple
logging.basicConfig(level=logging.DEBUG)
from kb_api import application

def verify_cb(conn, x509, err, depth, ret):
    # Called with the SSL.Connection, the X509 blob, err (errno from openssl),
    # verify depth, and ret (success or failure)
    logging.debug('set_verify callback: err=%s depth=%s ret=%s',
                  err, depth, ret)
    if ret == 1 and err == 0 and depth == 0:
        logging.debug('populating environment with x509 data')
    for k,v in x509.get_subject().get_components():
        kname = 'Email' if k == 'emailAddress' else k
        os.environ['SSL_CLIENT_S_DN_{0}'.format(kname)] = v
    return ret

class DebugMiddleware:
    def __init__(self, application):
        self.__application = application

    def __call__(self, environ, start_response):
        environ.update({k:v for k,v in os.environ.iteritems() if k.startswith('SSL_CLIENT_S_DN')})
        environ['KB_API_CONFIG'] = os.environ['KB_API_CONFIG']
        return self.__application(environ, start_response)

ssl_ctx = SSL.Context(SSL.TLSv1_METHOD)
# Required to use optional client verification
ssl_ctx.set_session_id(str(uuid.uuid4())[:31])
# The equivalent of verifyclient optional
# We'd want to add a or with VERIFY_FAIL_IF_NO_PEER_CERT to require
ssl_ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_CLIENT_ONCE , verify_cb)
ssl_ctx.use_privatekey_file('/home/jdreed/src/certs/localhost.key')
ssl_ctx.use_certificate_file('/home/jdreed/src/certs/localhost.crt')
ssl_ctx.load_verify_locations('/home/jdreed/src/certs/mitCAclient.pem', None)
run_simple('localhost', 8080, DebugMiddleware(application),
           use_reloader=True, ssl_context=ssl_ctx)



