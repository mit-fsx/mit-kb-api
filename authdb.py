#!/usr/bin/python

import logging
import sys

logging.basicConfig(level=logging.DEBUG)

from kb_api.config import APIConfig
from kb_api import auth
from optparse import OptionParser

def set_callback(option, opt_str, value, parser):
    optargs = []
    while len(parser.rargs) > 0 and not parser.rargs[0].startswith('-'):
        optargs.append(parser.rargs.pop(0))
    if len(optargs) == 0:
        parser.error("\n\tAt least one permission must follow '-s space_key'\n"
                     "\tUse 'NONE' to remove permissions")
    mode = 0
    for p in optargs:
        try:
            mode |= getattr(auth.Permissions, p.upper())
        except AttributeError:
            parser.error("Unknown permission '{0}'".format(p))
    if parser.values.permset is None:
        parser.values.permset = []
    parser.values.permset.append((value, mode))

parser = OptionParser()
parser.add_option("-i", dest="init", action="store_true",
                  default=False, help="Initialize database")
parser.add_option("-a", dest="add", action="store",
                  help="Add a user and print the key")
parser.add_option("-k", dest="key", action="store",
                  help="The user key to set permissions for (with -p)")
parser.add_option("-p", dest="permset", action="callback", default=None,
                  callback=set_callback, type="string",
                  help="Set permissions for SPACE to the positional args")
(options, args) = parser.parse_args()
if len(args) > 0:
    parser.error("does not take any positional arguments")
if options.init:
    if not all([x is None for x in [options.add,
                                    options.key,
                                    options.permset]]):
        parser.error("-i must be used by itself")
else:
    if options.key is not None and options.add is not None:
        parser.error("-k and -a are mutually exclusive")
    if options.key is None and options.add is None:
        parser.error("-a or -k is required")

if options.key is not None and options.permset is None:
    parser.error("-k requires -p")


with auth.AuthenticationContext() as ctx:
    if options.init:
        ctx.create_tables()
    else:
        if options.add is not None:
            user = ctx.add_user(options.add)
            print "Key for {0} is {1}".format(options.add,
                                              user.key)
        else:
            user = ctx.get_user(options.key)
        if user is None:
            print "Error getting user"
        else:
            if options.permset is not None:
                for p in options.permset:
                    user.set_permission(*p)

