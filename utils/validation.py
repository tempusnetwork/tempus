import os
import copy
import ecdsa
import jsonref
from utils.pki import verify, pubkey_to_addr
from jsonschema import validate
from utils.helpers import hasher, handle_exception, standard_encode
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


def validate_difficulty(hash):
    difficulty = config['difficulty']
    if hash[-difficulty:] == "0" * difficulty:
        return True
    else:
        return False


def validate_sig_hash(item):
    # The reason this is a combined check on sig+hash (instead of split methods)
    # Is that the check needs to be performed simultaneously
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
        print("Bad signature!" + str(item_copy) + " " + str(signature))
        return False

    return True


def validate_tick(tick):
    if not validate_schema(tick, 'tick_schema.json'):
        logger.debug("Failed schema validation")
        return False

    # Check hash and sig keeping in mind signature might be popped off
    if not validate_sig_hash(tick):
        logger.debug("Failed signature and hash checking")
        return False

    # Check all pings in list
    for ping in tick['list']:
        valid_ping = validate_ping(ping, check_in_pool=False)
        if not valid_ping:
            logger.debug("tick invalid due to containing invalid ping")
            return False

    # TODO: Check timestampdiff larger than X min
    # TODO: Check 90% of prev signatures included

    return True


def validate_ping(ping, pingpool, check_in_pool=True):
    if not validate_schema(ping, 'ping_schema.json'):
        logger.debug("Failed ping schema validation")
        return False

    # Check addr already not in dict
    if check_in_pool:
        if pubkey_to_addr(ping['pubkey']) in pingpool:
            logger.debug("Failed ping poolcheck validation")
            return False

    # Check hash and sig, keeping in mind signature might be popped off
    if not validate_sig_hash(ping):
        logger.debug("Failed ping check sighash validation")
        return False

    # TODO: Sanity check timestamp?
    # TODO: Check if ping references diff hash

    return True
