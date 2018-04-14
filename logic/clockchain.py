import json
import time
from utils.pki import get_kp, pubkey_to_addr, sign
from utils.helpers import utcnow, standard_encode, \
    hasher, mine, config, logger, dir_path
from utils.validation import validate_ping


class Clockchain(object):
    def __init__(self, messenger):
        self.chain = []
        self.pingpool = {}
        self.added_ping = False
        self.messenger = messenger

        # TODO: Figure out how to decide common genesis
        # tick if all start with diff hashes..
        # Use reward address as identifier for this node
        if config['generate_rand_addr']:
            self.pubkey, self.privkey = get_kp()
            self.addr = pubkey_to_addr(self.pubkey)
            logger.debug("Using random addr + privkey: " + self.privkey)
        else:
            # Assumes priv.json exists containing fixed private key
            # This file is in .gitignore so you don't publish your privkey..
            with open(dir_path + '/config/priv.json') as privkey_file:
                privkey = json.load(privkey_file)

            self.pubkey, self.privkey = get_kp(privkey=privkey['priv'])

            self.addr = pubkey_to_addr(self.pubkey)

        logger.debug("This node is " + self.addr)

        # Create genesis tick
        # TODO: Re-adapt this to use signatures
        genesis_addr = "tempigFUe1uuRsAQ7WWNpb5r97pDCJ3wp9"
        self.chain.append(
            {'addr': genesis_addr, 'nonce': 27033568337, 'list': []})

    def current_tick_ref(self):
        return hasher(self.chain[-1])

    def restart_tick(self):
        self.added_ping = False
        self.pingpool = {}


def ping_worker():
    while True:
        time.sleep(20)
        if not clockchain.added_ping:
            logger.debug("Havent pinged network this round! Starting to mine..")
            ping = {'pubkey': clockchain.pubkey,
                    'timestamp': utcnow(),
                    'reference': clockchain.current_tick_ref()}

            # Always do mining and put nonce after ping construction
            # but before inserting signature
            _, nonce = mine(ping)
            ping['nonce'] = nonce

            signature = sign(standard_encode(ping), clockchain.privkey)
            ping['signature'] = signature

            # Validate own ping
            if not validate_ping(ping, check_in_pool=True):
                logger.debug("Failed own ping validation")
                continue  # Skip to next iteration of while loop

            # Add to pool
            addr = pubkey_to_addr(ping['pubkey'])
            clockchain.pingpool[addr] = ping
            clockchain.added_ping = True

            # Forward to peers (this has to be at very end after all validation)
            messenger.forward(ping, 'ping', clockchain.addr)
            logger.debug("Forwarded own ping: " + str(ping))


# TODO: Consensus mechanism
def tick_worker():
    while True:
        if clockchain.added_ping:
            pass