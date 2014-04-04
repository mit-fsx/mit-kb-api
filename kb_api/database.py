import logging

import sqlalchemy as sql
from sqlalchemy.ext import declarative

from .config import APIConfig

logger = logging.getLogger('kb_api.database')
dbname = APIConfig().get('Authentication', 'dbname')
engine = sql.create_engine('sqlite:///{0}'.format(dbname))
logger.debug('Using db: {0}'.format(dbname))
db_session = sql.orm.scoped_session(sql.orm.sessionmaker(bind=engine))
# the Base class for the ORM
Base = declarative.declarative_base()
Base.query = db_session.query_property()

@sql.event.listens_for(sql.engine.Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

def init_db():
    # Yes, this is here on purpose, because of sqlalchemy magic
    from . import models
    Base.metadata.create_all(bind=engine)

def _create_db():
    logger.info("Dropping tables")
    Base.metadata.drop_all(bind=engine)
    logger.info("Creating tables")
    Base.metadata.create_all(bind=engine)

    
