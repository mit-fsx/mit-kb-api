import logging
import os.path
import re
import sqlite3
import uuid

from datetime import datetime, timedelta

logger = logging.getLogger('kb_api.auth')

schema = { 'users': [( 'id', 'integer primary key autoincrement'),
                     ('email', 'varchar'),
                     ('description', 'varchar'),
                     ('expires', 'timestamp'),
                     ('created', 'timestamp'),
                     ('api_key', 'varchar(36)')],

           'permissions': [('id', 'integer'),
                           ('space', 'varchar'),
                           ('permissions', 'integer')]
           }

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
    NONE = 0
    READ = 1
    WRITE = 2

    ANONYMOUS_SPACES = ('istcontrib',)

    def __init__(self, *permissions):
        logger.debug("Initializing new Permissions object with: %s",
                     permissions)
        if len(permissions) == 0:
            for s in self.ANONYMOUS_SPACES:
                self[s] = Permissions.READ
        for k,v in permissions:
            if k in self.__dict__:
                logger.error("Duplicate Permissions value for %s", k)
                raise ValueError('Permission set has duplicate entries!')
            self[k] = v

    def __setitem__(self, key, value):
        if not isinstance(value, int):
            raise ValueError("Mode bits must be integers")
        logger.debug("Setting %s to %d", key, value)
        self.__dict__[key] = value

    def __repr__(self):
        return "{0}({1})".format(self.__class__.__name__,
                                      ', '.join(
                ["{0}={1}".format(*x) for x in self.__dict__.items()]))

    def items(self):
        return self.__dict__.items()

    def __len__(self):
        return len(self.__dict__)

    def __iter__(self):
        return self.__dict__.iteritems()

    def __contains__(self, item):
        return item in self.__dict__

    def __getitem__(self, key):
        logger.debug("Returning NONE for %s", key)
        return self.__dict__.get(key, Permissions.NONE)

    def __getattr__(self, attr):
        if not attr.startswith('_'):
            return self[attr]
        raise AttributeError("Permissions instance has no attribute '{0}'".format(attr))

class AuthenticationError(Exception):
    pass

class APIUser:
    def __init__(self, context, uid, expiration=None):
        self.uid = uid
        self.expires = expiration
        if expiration is not None and not isinstance(expiration, datetime):
            raise ValueError('expiration must be a datetime.datetime')
        self.permissions = context._get_permissions(uid)

    def __repr__(self):
        return "{0}({1}, {2}, {3})".format(self.__class__.__name__,
                                           self.uid, self.expires, self.permissions)

    def can(self, op, space):
        logger.debug("Checking for %d on %s", op, space)
        return (getattr(self.permissions, space) & op) != 0
    
    @property
    def anonymous(self):
        return self.uid is None

    @property
    def expired(self):
        # An anonymous login never "expires"
        if self.expires is None:
            return False
        return self.expires <= datetime.now()
        
    @property
    def authenticated(self):
        return not self.anonymous and not self.expired

class AuthenticationContext:
    def __init__(self, dbname):
        if not os.path.isfile(dbname):
            raise AuthenticationError(
                'Database {0} does not exist.'.format(dbname))
        self.conn = sqlite3.connect(dbname,
                                    detect_types=sqlite3.PARSE_DECLTYPES)
        self._ensure_schema()
        logger.debug("AuthenticationContext initialized")
    
    def _ensure_schema(self):
        # TODO: verify columns
        with self.conn:
            c = self.conn.cursor()
            for table in schema.keys():
                c.execute(
                    "SELECT name FROM sqlite_master WHERE name=? AND type=?",
                    (table, 'table'))
                if c.fetchone() is None:
                    raise AuthenticationError('Database corrupt.')

    def get_user(self, api_key):
        # TODO: use 'Row' type?
        if api_key is None:
            logger.debug("api_key=None, returning empty user")
            return APIUser(self, None)
        if not isinstance(api_key, str):
            raise ValueError("api_key was not a string")
        sql = 'SELECT id, expires FROM users WHERE api_key=?'
        vals = (api_key,)
        with self.conn:
            logger.debug("Looking up api key %s", api_key)
            c = self.conn.cursor()
            c.execute(sql, vals)
            r = c.fetchone()
            if r is None:
                logger.debug("Not found")
                return APIUser(self, None)
            return APIUser(self, *r)

    def _get_permissions(self, user_id):
        if user_id is None:
            logger.debug("Returning empty permissions object")
            return Permissions()
        sql = 'SELECT space, permissions FROM permissions WHERE id=?'
        vals = (user_id,)
        with self.conn:
            # TODO: consolidate query code
            c = self.conn.cursor() 
            c.execute(sql, vals)
            r = c.fetchall()
            logger.debug("Permissions for %d: %s", user_id, r)
            return Permissions(*r)

    def add_user(self, email, n_days_lifetime=365, description=''):
        logger.debug("Adding new user %s (%d days)", email, n_days_lifetime)
        sql = "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)"
        now = datetime.now()
        then = now + timedelta(days=n_days_lifetime)
        api_key = str(uuid.uuid4())
        vals = (None, email, description, then, now, api_key)
        with self.conn:
            c = self.conn.cursor()
            c.execute(sql, vals)
        return api_key

    def _del_permissions(self, uid):
        sql = "DELETE FROM permissions WHERE id=?"
        with self.conn:
            logger.debug("Deleting permissions for uid %d", uid)
            c = self.conn.cursor()
            c.execute(sql, (uid,))

    def _add_permissions(self, uid, *args):
        if len(args) < 1:
            raise ValueError("Must pass at least one set of permissions")
        if not all([isinstance(x, tuple) for x in args]):
            raise TypeError("Must pass tuples of (space, permission)")
        sql = "INSERT INTO permissions VALUES (?, ?, ?)"
        with self.conn:
            logger.debug("Adding permissions for uid %d: %s", uid, args)
            c = self.conn.cursor()
            c.executemany(sql, [(uid,) + perm for perm in args])

    def set_permissions(self, uid, permissions):
        self._del_permissions(uid)
        self._add_permissions(uid, *permissions.items())

    @staticmethod
    def _create_schema(dbname):
        # TODO: This will fail once we hit 2^63-1 users, deal with SQLite Full
        #       exception at some point
        # TODO: sanity check filename
        db_conn = sqlite3.connect(dbname)
        with db_conn:
            for table in schema.keys():
                cols = ', '.join([' '.join(col) for col in schema[table]])
                # String substitution is fine here since these are static
                # values not provided by the user.
                db_conn.execute("DROP TABLE IF EXISTS {table}".format(
                        table=table))
                db_conn.execute("CREATE TABLE {table} ({columns})".format(
                        table=table, columns=cols))


