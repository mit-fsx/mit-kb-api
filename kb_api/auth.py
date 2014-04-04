import logging
import re
import uuid

import sqlalchemy as sql
from sqlalchemy.ext import declarative

from .config import APIConfig
from datetime import datetime

logger = logging.getLogger('kb_api.auth')
config = APIConfig()
# the Base class for the ORM
Base = declarative.declarative_base()
dbname = config.get('Authentication', 'dbname')
engine = sql.create_engine('sqlite:///{0}'.format(dbname),
                           poolclass=sql.pool.StaticPool)
session = sql.orm.sessionmaker(bind=engine)()

logger.debug('Using db: {0}'.format(dbname))

@sql.event.listens_for(sql.engine.Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

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

class Permission(Base):
    """The representation of a single permission in the DB"""
    __tablename__ = "permissions"
    
    uid = sql.Column(sql.Integer, sql.ForeignKey("users.id"))
    space_key = sql.Column(sql.String(64))
    permissions = sql.Column(sql.Integer)

    __table_args__ = (sql.PrimaryKeyConstraint(uid, space_key),)

class Status(Base):
    """Lookup table for statuses"""
    __tablename__ = 'status'

    id = sql.Column(sql.Integer, sql.Sequence('status_id_seq'), primary_key=True)
    value = sql.Column(sql.String(32), unique=True)

class AnonymousUser:
    """The Anonymous User."""
    permissions = {'istcontrib': Permissions.READ,
                   }

    @staticmethod
    def can(op, space):
        return space in AnonymousUser.permissions and \
            (AnonymousUser.permissions[space] & op) != 0
    
class User(Base):
    """Representation of a 'user' in the database"""
    __tablename__ = 'users'

    id = sql.Column(sql.Integer, sql.Sequence('user_id_seq'), primary_key=True)
    email = sql.Column(sql.String(50))
    description = sql.Column(sql.String(128))
    created = sql.Column(sql.DateTime())
    status = sql.Column(sql.Integer, sql.ForeignKey("status.id"))
    key = sql.Column(sql.String(36), unique=True)

    permissions = sql.orm.relationship("Permission", backref="user")

    def __repr__(self):
        return "User({0}, {1}, {2})".format(self.email,
                                            Statuses.readable(self.status),
                                            self.key)

    def _get_permission(self, space):
        perms = [x for x in self.permissions if x.space_key == space]
        if len(perms) > 1:
            raise AuthenticationError(
                "DB error: user %d has multiple perms %s".format(self.id, space)
                )
        return perms[0] if len(perms) else None

    def can(self, op, space):
        perm = self._get_permission(space)
        return False if perm is None else (op & perm.permissions != 0)

    def set_permission(self, space, *mode):
        perms = reduce(lambda x, y: x | y, mode)
        perm = self._get_permission(space)
        if perm is None:
            self.permissions.append(Permission(space_key=space, permissions=perms))
        else:
            perm.permissions = perms

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

    def readable(self, status):
        if status not in self._status_dict.values():
            raise AttributeError("No Status id {0}".format(status))
        return [k for k,v in self._status_dict.items() if v == status][0]

    @property
    def all(self):
        return [Status(value=x) for x in self._all]
    

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
        return self.user is not None and self.user.status == Statuses.ACTIVE

class AuthenticationContext:
    def __init__(self):
        logger.debug("AuthenticationContext initialized")
        Base.metadata.create_all(engine)
        
    def __enter__(self):
        logger.debug("AuthenticationContext enter")
        global Statuses
        Statuses = _Statuses(*session.query(Status).all())
        return self

    def __exit__(self, exception_type, exception_val, trace):
        logger.debug("AuthenticationContext exit")
        global Statuses
        Statuses = _Statuses()
        if exception_type is None:
            session.commit()
            return True
        return False

    def get_user(self, api_key):
        if api_key is None:
            raise ValueError("api_key cannot be None")
        try:
            return session.query(User).filter(User.key == api_key).one()
        except sql.orm.exc.NoResultFound:
            return None
        except sql.orm.exc.NoResultFound:
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
                 'status': Statuses.ACTIVE,
                 'key': str(uuid.uuid4()),
                 'email': email,
                 'created': datetime.now(),
                }
        vals.update(kwargs)
        user = User(**vals)
        logger.debug("Adding user: %s", user)
        session.add(user)
        for space in AnonymousUser.permissions:
            user.set_permission(space, AnonymousUser.permissions[space])
        return user

    def create_tables(self):
        logger.info("Dropping tables")
        Base.metadata.drop_all(engine)
        logger.info("Creating tables")
        Base.metadata.create_all(engine)
        logger.info("Populating 'status' table")
        for status in Statuses.all:
            session.add(status)
