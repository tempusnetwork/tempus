import pytz
import socket
import random
import json
import os.path
import logging
import hashlib
from datetime import datetime

# Global variables
config_path = os.path.dirname(os.path.realpath(__file__))
dir_path = os.path.abspath(os.path.join(config_path, os.pardir))
logger = logging.getLogger('clocklog')

with open(config_path + '/config.json') as config_file:
    config = json.load(config_file)


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
