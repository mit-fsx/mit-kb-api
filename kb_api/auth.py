import logging
import re
import uuid

from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from .database import init_db, db_session, _create_db
from . import models

from datetime import datetime

logger = logging.getLogger('kb_api.auth')

class AuthenticationError(Exception):
    pass

class Token:
    _re = re.compile(r'bearer ([\w\-]+)$')

    @staticmethod
    def extract(string):
        logger.debug('Attempting to extract token from: %s', string)
        match = Token._re.match(string)
        rv = None
        if match is not None:
            rv = match.group(1)
        logger.debug('Returning match: %s', rv)
        return rv

class Permissions:
    """
    An enum of permissions
    """
    NONE = 0x00
    READ = 0x01
    WRITE = 0x02
    WRITELABELS = 0x04

class AnonymousUser:
    """The Anonymous User."""
    permissions = {'istcontrib': Permissions.READ,
                   }

    @staticmethod
    def can(op, space):
        return space in AnonymousUser.permissions and \
            (AnonymousUser.permissions[space] & op) != 0
    
class _Statuses:
    """Hack for treating this like a dynamic ENUM"""
    _all = ('ACTIVE', 'REVOKED', 'EXPIRED', 'RESERVED')

    def __init__(self, *statuses):
        self._statuses = statuses
        self._status_dict = {s.value: s.id for s in self._statuses}

    def __getattr__(self, attr):
        # There's probably a better way
        if len(self._statuses) == 0:
            raise AuthenticationError("Cannot use Statuses outside AuthenticationContext")
        return self._status_dict[attr]

    @property
    def all(self):
        return [models.Status(value=x) for x in self._all]
    

Statuses = _Statuses()

class APIUser:
    def __init__(self, user=None):
        self.user = user

    def __repr__(self):
        return "{0}({1})".format(self.__class__.__name__, self.user)

    def can(self, op, space):
        logger.debug("Checking for %d on %s", op, space)
        if self.user is None:
            rv = AnonymousUser.can(op, space)
        elif not self.authenticated:
            rv = False
        else:
            rv = self.user.can(op, space)
        logger.debug("Returning %s", rv)
        return rv
    
    @property
    def anonymous(self):
        return self.user is None

    @property
    def authenticated(self):
        return self.user is not None and self.user.status_id == Statuses.ACTIVE

class AuthenticationContext:
    def __init__(self):
        init_db()
        global Statuses
        Statuses = _Statuses(*models.Status.query.all())
        
    def __enter__(self):
        logger.debug("AuthenticationContext enter")
        return self

    def __exit__(self, exception_type, exception_val, trace):
        logger.debug("AuthenticationContext exit")
        if exception_type is None:
            db_session.commit()
            return True
        return False

    def get_user(self, api_key):
        if api_key is None:
            raise ValueError("api_key cannot be None")
        try:
            return db_session.query(models.User).filter(models.User.key == api_key).one()
        except NoResultFound:
            return None
        except MultipleResultsFound:
            raise AuthenticationError("The DB is corrupt")
            logger.exception("Multiple db results for API key '%s'; shouldn't happen",
                             api_key)

    def lookup_user(self, api_key):
        logger.debug("Looking up %s", api_key)
        if api_key is None:
            return APIUser()
        user = self.get_user(api_key)
        return None if user is None else APIUser(user)
    
    def add_user(self, email, **kwargs):
        vals = { 'description': '',
                 'status_id': Statuses.ACTIVE,
                 'key': str(uuid.uuid4()),
                 'email': email,
                 'created': datetime.now(),
                }
        vals.update(kwargs)
        user = models.User(**vals)
        logger.debug("Adding user: %s", user)
        db_session.add(user)
        for space in AnonymousUser.permissions:
            user.set_permission(space, AnonymousUser.permissions[space])
        return user

    def create_tables(self):
        _create_db()
        logger.info("Populating 'status' table")
        for status in Statuses.all:
            db_session.add(status)
