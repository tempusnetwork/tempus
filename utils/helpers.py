import json
import pytz
import socket
import random
import hashlib
from utils.common import logger, config
from datetime import datetime
import traceback
import requests
import time
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
    if 'list' in tick and len(tick['list']) > 0 \
            and 'timestamp' in tick['list'][0]:
        ts_list = [ping['timestamp'] for ping in tick['list']]
        return median(ts_list)
    else:
        return None


def measure_tick_continuity(tick_dict, chain):
    extended_chain = chain + [tick_dict]  # the [] appends tick_dict at end

    continuity_dict = {}
    tot_sum = 0
    # TODO: Do running calculation in clockchain instead
    # TODO: so we dont recalculate this every time?

    # Traverse block-tree backwards
    for idx, possible_ticks in enumerate(reversed(extended_chain)):
        if idx == 0:
            tick_itself = list(possible_ticks.values())[0]
            chosen_tick = tick_itself
            prev_ref = tick_itself['prev_tick']
        else:
            chosen_tick = possible_ticks[prev_ref]
            prev_ref = chosen_tick['prev_tick']

        for ping in chosen_tick['list']:
            if ping["pubkey"] in continuity_dict:
                continuity_dict[ping["pubkey"]] += 1
            else:
                continuity_dict[ping["pubkey"]] = 1

    # TODO: Is this not gameable by having tons of pubkeys/ticks/pings?
    for pubkey in continuity_dict:
        tot_sum += continuity_dict[pubkey]

    if len(extended_chain) == 0:
        return 0

    return tot_sum / len(extended_chain)


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


# Function to make a request.post/.get, with an option to allow retries
def attempt(request, retry, **kwargs):
    if retry:
        retries = config['max_request_retries']
    else:
        retries = 0

    times_tried = 0
    while True:
        try:  # Only passing **kwargs because *args used for req.type and retry
            result = request(**kwargs)
            return result, True
        except requests.exceptions.ReadTimeout:
            times_tried += 1
            time.sleep(config['request_retries_sleep'])
            if times_tried >= retries:
                return None, False
            pass
        except requests.exceptions.ConnectionError:
            times_tried += 1
            time.sleep(config['request_retries_sleep'])
            if times_tried >= retries:
                return None, False
            pass
        except Exception as e:
            times_tried += 1
            handle_exception(e)
            time.sleep(config['request_retries_sleep'])
            if times_tried >= retries:
                return None, False
            pass


def handle_exception(exception):
    logger.exception("Exception of type " + str(type(exception)) +
                     " occurred, see log for more details", exc_info=False)
    logger.debug(traceback.format_exc())
