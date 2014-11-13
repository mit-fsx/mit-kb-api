import logging

# Set up logging here
logger = logging.getLogger('kb_api')
logger.addHandler(logging.NullHandler())

from .config import APIConfig as config

log_level = config.get('Logging', 'level', 'WARNING')
log_file = config.get('Logging', 'file', None)
hdlr = None
if log_file is not None:
    try:
        hdlr = logging.FileHandler(log_file)
    except IOError as e:
        logger.error("kb_api: Cannot log to file: {0}".format(e))
if hdlr is not None:
    hdlr.setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(message)s'))
    logger.addHandler(hdlr)
    if config.get('Logging', 'logsql', 'no') == 'yes':
        logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
        logging.getLogger('sqlalchemy.engine').addHandler(hdlr)
    logger.setLevel(getattr(logging, log_level))
