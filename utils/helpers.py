import pytz
import socket
import random
import json
import os.path
import logging
import hashlib
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

# Global variables
config_path = os.path.dirname(os.path.realpath(__file__))
dir_path = os.path.abspath(os.path.join(config_path, os.pardir))
logger = logging.getLogger('clocklog')
with open(config_path + '/config.json') as config_file:
    config = json.load(config_file)

# Logging set up
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

# Print to console as well
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(console_formatter)
logger.addHandler(console)


# Global methods
def utcnow():
    return int(datetime.now(tz=pytz.utc).timestamp())


def remap(mapping):
    return [{'key': k, 'value': v} for k, v in mapping.items()]


def resolve(ip):
    return socket.gethostbyaddr(ip)[0]


# Encode dicts (messages loaded from JSON for example) in standard way
def standard_encode(dictionary):
    return bytes(
        json.dumps(dictionary, sort_keys=True, separators=(',', ':')),
        'utf-8')


def hasher(dictionary):
    return hashlib.sha256(standard_encode(dictionary)).hexdigest()


# TODO: Do this in C or other efficient lib..
def mine(content=None):
    # Importing here to avoid circular dependency
    from utils.validation import validate_difficulty
    nonce = random.randrange(config['max_randint'])
    while True:
        content['nonce'] = nonce
        hashed = hasher(content)
        if validate_difficulty(hashed):
            break
        nonce += random.randrange(config['nonce_jump'])
    return hashed, nonce
