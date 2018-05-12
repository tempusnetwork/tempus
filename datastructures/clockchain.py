from utils.helpers import hasher
from utils.common import logger, credentials
import copy


class Clockchain(object):
    def __init__(self):
        self.chain = []
        self.ping_pool = {}

        logger.debug("This node is " + credentials.addr)

        # TODO: Create valid genesis tick
        genesis_tick = {"not_yet_implemented": True}
        self.chain.add_tick(genesis_tick)

    def current_tick_ref(self):
        last_block_copy = copy.deepcopy(self.chain[-1])

        # Removing signature and this_tick in order to return correct hash
        last_block_copy.pop('signature', None)
        last_block_copy.pop('this_tick', None)

        return hasher(last_block_copy)

    def restart_tick(self):
        self.ping_pool = {}

    def active_chain(self):
        # TODO: Return chain with longest cumulative continuity?
        return self.chain

    def add_tick(self, tick):
        return tick
