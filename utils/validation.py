import os
import copy
import ecdsa
import jsonref
from utils.pki import verify, pubkey_to_addr
from jsonschema import validate

from utils.helpers import hasher, handle_exception, standard_encode, median_ts
from utils.helpers import utcnow

from utils.common import config, dir_path, logger


def validate_schema(dictionary, schema_file):
    absolute_path = dir_path + '/schemas/' + schema_file

    base_path = os.path.dirname(absolute_path)
    base_uri = 'file://{}/'.format(base_path)

    with open(absolute_path) as schema_bytes:
        schema = jsonref.loads(schema_bytes.read(), base_uri=base_uri,
                               jsonschema=True)
    try:
        validate(dictionary, schema)
    except Exception as e:
        handle_exception(e)
        return False
    return True


def validate_difficulty(hash_to_check):
    difficulty = config['difficulty']

    if hash_to_check[-difficulty:] != "0" * difficulty:
        return False

    return True


def validate_tick_timediff(tick):
    # Median timestamp of tick must be at least config['tick_period'] ago
    median = median_ts(tick)

    utc_now = utcnow()
    if not median + \
            config['cycle_time_multiplier']*config['cycle_time'] < utc_now:
        return False

    return True


def validate_ping_timestamp(ping):
    return True


def validate_sig_hash(item):
    # The reason this is a combined check on sig+hash (instead of split methods)
    # Is that check must be atomic, as sig+hash mutate the tick in certain order

    # Deepcopy used to not modify instance we received
    item_copy = copy.deepcopy(item)
    signature = item_copy.pop('signature', None)

    if signature is None:
        logger.debug("Could not find signature in validate sighash..")
        return False

    # Check hash
    if not validate_difficulty(hasher(item_copy)):
        logger.debug("Invalid hash for item: "
                     + str(item_copy) + " "
                     + hasher(item_copy))
        return False

    # Validate signature
    try:
        encoded_message = standard_encode(item_copy)
        if not verify(encoded_message, signature, item_copy['pubkey']):
            return False
    except ecdsa.BadSignatureError:
        # TODO : When new joiner joins, make sure peers relay latest hash
        logger.debug("Bad signature!" + str(item_copy) + " " + str(signature))
        return False

    return True


def validate_tick(tick, previous_tick=None, possible_previous_ticks=None,
                  verbose=True):
    # Doing validation on a copy so that the original keeps its "this_tick" ref
    # Otherwise the tick dict will be modified by any operations done here
    tick_copy = copy.deepcopy(tick)
    prev_tick_copy = copy.deepcopy(previous_tick)

    # This is used to keep track of the hash of the tick as debug information
    # Popping it off as it is not supposed to be an actual part of a tick
    tick_copy.pop('this_tick', None)

    if not validate_schema(tick_copy, 'tick_schema.json'):
        logger.debug("Tick failed schema validation")
        return False

    # Check hash and sig keeping in mind signature might be popped off
    if not validate_sig_hash(tick_copy):
        logger.debug("Tick failed signature and hash checking")
        return False

    if previous_tick is not None:
        if tick_copy['height'] != prev_tick_copy['height'] + 1:
            logger.debug("Tick failed height check")
            return False

    if possible_previous_ticks is not None:
        if not tick_copy['prev_tick'] in possible_previous_ticks:
            logger.debug("Tick failed referencing any 1 of prev possible ticks")
            return False

    # TODO: This forces lower bound, but should also include upper bound?
    if not validate_tick_timediff(prev_tick_copy):  # Verbose: fails often
        logger.debug("Tick failed minimum timediff check") if verbose else None
        return False

    # Check all pings in list
    for ping in tick_copy['list']:
        # TODO: Check if tick's pings are in my own pool?
        # TODO: So they dont just send any random pings
        valid_ping = validate_ping(ping)
        if not valid_ping:
            logger.debug("tick invalid due to containing invalid ping")
            return False

    return True


def validate_ping(ping, ping_pool=None, vote=False):
    stage = 'vote' if vote else 'ping'
    if not validate_schema(ping, 'ping_schema.json'):
        logger.debug(stage + " failed schema validation")
        return False

    if ping_pool is not None:
        if vote:
            if pubkey_to_addr(ping['pubkey']) not in ping_pool:
                logger.debug("Voters's pubkey not found in pingpool")
                return False

            # Voting twice just overwrites your past vote!
        else:
            if pubkey_to_addr(ping['pubkey']) in ping_pool:
                logger.debug(stage + " was already in pool")
                return False

    # Check hash and sig, keeping in mind signature might be popped off
    if not validate_sig_hash(ping):
        logger.debug(stage + " failed sighash validation")
        return False

    # TODO: Do sanity check on a pings timestamp in relation to current time etc
    if not validate_ping_timestamp(ping):  # <-- empty stub function atm..
        logger.debug(stage + " failed sanity check on timestamp")
        return False

    return True
