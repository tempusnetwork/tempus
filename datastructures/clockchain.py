from utils.helpers import hasher
from utils.common import logger, credentials
import copy


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
        last_block_copy = copy.deepcopy(self.chain[-1])

        # Removing signature and this_tick in order to return correct hash
        last_block_copy.pop('signature', None)
        last_block_copy.pop('this_tick', None)

        return hasher(last_block_copy)

    def restart_tick(self):
        self.ping_pool = {}
