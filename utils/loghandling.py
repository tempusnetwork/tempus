import os
import logging
from logging.handlers import TimedRotatingFileHandler
from main import config

# Set up logging
logger = logging.getLogger('clocklog')

logging_formatter = logging.Formatter(fmt=
                                      '%(asctime)s %(module)s %(threadName)s'
                                      ' %(levelname)s: %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')
console_formatter = logging.Formatter(fmt=
                                      '%(asctime)s %(module)-20s '
                                      '%(threadName)-20s'
                                      '%(levelname)-8s: '
                                      '%(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')

# Dated files for logging
os.makedirs(os.path.dirname(config['log_file']), exist_ok=True)
handler = TimedRotatingFileHandler(config['log_file'], backupCount=3,
                                   interval=1, when="d")
handler.suffix = "%Y-%m-%d.log"

handler.setFormatter(logging_formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

# TODO: Put console level at INFO so you dont see all debug messages
# Print logging to console as well
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(console_formatter)
logger.addHandler(console)
