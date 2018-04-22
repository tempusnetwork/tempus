import json
from utils.pki import pubkey_to_addr, get_kp
from utils.helpers import hasher
from utils.loghandling import logger
from main import config, dir_path


class Clockchain(object):
    def __init__(self):
        # Use reward address as identifier for this node
        if config['generate_rand_addr']:
            pubkey, privkey = get_kp()
            logger.debug("Using random addr + privkey: " + privkey)
        else:
            # Assumes priv.json exists containing fixed private key
            # This file is in .gitignore so you don't publish your privkey..
            with open(dir_path + '/utils/priv.json') as privkey_file:
                privkey = json.load(privkey_file)
            pubkey, privkey = get_kp(privkey=privkey['priv'])

        self.privkey = privkey
        self.pubkey = pubkey
        self.addr = pubkey_to_addr(self.pubkey)

        self.chain = []
        self.pingpool = {}
        self.added_ping = False

        logger.debug("This node is " + self.addr)

        # TODO: Figure out how to decide common genesis tick if diff starthash
        # TODO: Re-adapt this to use signatures
        genesis_addr = "tempigFUe1uuRsAQ7WWNpb5r97pDCJ3wp9"
        self.chain.append(
            {'addr': genesis_addr, 'nonce': 27033568337, 'list': []})

    def current_tick_ref(self):
        return hasher(self.chain[-1])

    def restart_tick(self):
        self.added_ping = False
        self.pingpool = {}
