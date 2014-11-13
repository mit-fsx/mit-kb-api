#!/usr/bin/python

import logging
import os
import sys

from optparse import OptionParser

logging.basicConfig(level=logging.DEBUG if os.environ.has_key('KB_API_DEBUG') else logging.ERROR)

from kb_api import admin, auth
from kb_api.database import db

def ask(question, default=None, answers=None,
        interrupt=None, want_bool=None):
    if answers is None:
        answers = ('y', 'n') 
    if len(set(answers)) != len(answers):
        raise ValueError("answers must be unique")
    if len(answers) < 2:
        raise ValueError("Must have at 2 answers")
    if want_bool is None:
        want_bool = len(answers) == 2
    elif want_bool and len(answers) != 2:
        raise ValueError("Can only return boolean with 2 answers")
    if not all([isinstance(x, basestring) for x in answers]):
        raise ValueError("Answers must be strings")
    if default is not None and default not in answers:
        raise ValueError("default must be in answers")
    if interrupt is not None and interrupt not in answers:
        raise ValueError("interrupt must be in answers")
    prompt = '/'.join(map(lambda x: x.upper() if x == default else x, answers))
    valid_answers = [x.lower() for x in answers]
    while True:
        try:
            ans = raw_input("{0} [{1}] ".format(question, prompt)).strip().lower()
        except KeyboardInterrupt:
            if interrupt is not None:
                ans = interrupt
            else:
                raise
        if len(ans) < 1:
            if default is None:
                continue
            ans = default
        if ans not in answers:
            print >>sys.stderr, "Please enter a valid answer: ", answers
            continue
        break
    if want_bool:
        return answers.index(ans) == 0
    return ans

parser = OptionParser()
parser.add_option("-i", dest="init", action="store_true",
                  default=False, help="Initialize database")
parser.add_option("-a", dest="add", action="append",
                  metavar="user email realname", nargs=3,
                  help="Add an administrative user")
parser.add_option("-y", dest="yes", action="store_true",
                  default=False, help="Do not prompt for confirmation")

(options, args) = parser.parse_args()
if len(args) > 0:
    parser.error("does not take any positional arguments")

if not options.init and options.add is None:
    parser.error("At least one option is required.")

with admin.app.test_request_context():
    if options.init:
        if options.yes or ask("Create the database tables?", default='n'):
            auth.create_tables()
            print "Created tables."
            if not options.add:
                print >>sys.stderr, "WARNING: No administrators defined.  Please add one."
    if options.add is not None:
        for userdata in options.add:
            uname,email,realname = userdata
            user = auth.lookup_user(uname)
            if user is not None:
                if options.yes or ask("User exists.  Make them admin?", default='y'):
                    auth.update_db_object(user, ('is_admin',), {'is_admin': True})
                    print "User updated."
            elif options.yes or ask("Add {0} ({1}) as administrator?".format(realname, uname), default='y'):
                auth.add_user(username=uname,
                              email=email,
                              real_name=realname,
                              is_admin=True)
                print "Added", uname
sys.exit(0)
