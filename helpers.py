import os
import pytz
import json
import socket
import random
import logging
import hashlib
import coloredlogs
from datetime import datetime
from validation import validate_difficulty
from logging.handlers import TimedRotatingFileHandler

dir_path = os.path.dirname(os.path.realpath(__file__))

with open(dir_path + '/config/config.json') as config_file:
    config = json.load(config_file)

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
logger = logging.getLogger('clocklog')
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

# Print to console as well
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(console_formatter)
logging.getLogger('clocklog').addHandler(console)

coloredlogs.install(level='DEBUG', logger=logger,
                    fmt='(%(threadName)-10s) (%(funcName)s) %(message)s')


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
    nonce = random.randrange(config['max_randint'])
    while True:
        content['nonce'] = nonce
        hashed = hasher(content)
        if validate_difficulty(hashed):
            break
        nonce += random.randrange(config['nonce_jump'])
    return hashed, nonce
