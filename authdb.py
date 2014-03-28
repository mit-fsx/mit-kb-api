#!/usr/bin/python

import logging
import sys

sys.path.insert(0, '/var/www/kb_api/lib')

from kb_api.config import APIConfig
from kb_api.auth import AuthenticationContext, Permissions

def usage():
    print """Usage: {0} [init | add email_addr]""".format(sys.argv[0])
    sys.exit(1)

logging.basicConfig(level=logging.DEBUG)

config = APIConfig()
dbname =  config.get('Authentication', 'dbname')
print >>sys.stderr, "Using {0}".format(dbname)

if len(sys.argv) < 2:
    usage()

if sys.argv[1] not in ('init', 'add'):
    usage()

if sys.argv[1] == 'init':
    AuthenticationContext._create_schema(dbname)
    sys.exit(0)

ctx = AuthenticationContext(dbname)
api_key = ctx.add_user(sys.argv[2])
user = ctx.get_user(api_key)
for space in sys.argv[3:]:
    p = Permissions.READ
    if space.startswith('+'):
        p = Permissions.WRITE | Permissions.READ
    user.permissions[space.lstrip('+')] = p
ctx.set_permissions(user.uid, user.permissions)
print api_key
sys.exit(0)
