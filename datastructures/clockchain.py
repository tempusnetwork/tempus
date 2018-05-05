from utils.helpers import hasher
from utils.common import logger, credentials


class Clockchain(object):
    def __init__(self):

        self.chain = []
        self.ping_pool = {}

        logger.debug("This node is " + credentials.addr)

        # TODO: Figure out how to decide common genesis tick if diff starthash
        # TODO: Re-adapt this to use signatures
        genesis_addr = "tempigFUe1uuRsAQ7WWNpb5r97pDCJ3wp9"
        self.chain.append(
            {'addr': genesis_addr, 'nonce': 27033568337, 'list': []})

    def current_tick_ref(self):
        return hasher(self.chain[-1])

    def restart_tick(self):
        self.ping_pool = {}
