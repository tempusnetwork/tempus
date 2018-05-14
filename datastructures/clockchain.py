from utils.helpers import hasher
from utils.common import logger, credentials, config
from queue import Queue
import copy


class Clockchain(object):
    def __init__(self):
        self.chain = Queue(maxsize=config['chain_max_length'])
        self.ping_pool = {}
        self.tick_pool = {}

        logger.debug("This node is " + credentials.addr)

        # TODO: Create valid genesis tick
        self.active_tick = {
            'pubkey': 'pubkey',
            'nonce': 0,
            'list': [],
            'prev_tick': 'prev_tick',
            'height': 0,
            'signature': 'signature'
        }
        self.add_to_tick_pool(self.active_tick)

    def current_tick_ref(self):
        last_block_copy = copy.deepcopy(self.active_tick)

        # Removing signature and this_tick in order to return correct hash
        last_block_copy.pop('signature', None)
        last_block_copy.pop('this_tick', None)

        return hasher(last_block_copy)

    def current_height(self):
        return self.active_tick['height']

    def restart_cycle(self):
        self.ping_pool = {}
        self.tick_pool = {}

    def add_to_tick_pool(self, tick):
        # Make sure first tick received is the active tick
        if not self.tick_pool:
            self.active_tick = tick

        tick_copy = copy.deepcopy(tick)

        this_tick_ref = tick_copy.pop('this_tick', None)
        if this_tick_ref is not None:
            self.tick_pool[this_tick_ref] = tick_copy

    def consolidate_ticks_to_chain(self):
        # TODO: PRUNING!! GO from 100 candidate ticks to max 2-3 in the pool

        if self.chain.full():
            # This removes earliest item from queue
            self.chain.get_nowait()

        self.chain.put(self.tick_pool)

