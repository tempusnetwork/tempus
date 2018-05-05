import json
import pytz
import socket
import random
import hashlib
from utils.common import logger, config
from datetime import datetime
import traceback
from statistics import median


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


def median_ts(tick):
    ts_list = [ping['timestamp'] for ping in tick['list']]
    return median(ts_list)


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


def handle_exception(exception):
    logger.exception("Exception of type " + str(type(exception)) +
                     " occurred, see log for more details", exc_info=False)
    logger.debug(traceback.format_exc())
