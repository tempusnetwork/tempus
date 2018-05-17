from utils.helpers import hasher, measure_tick_continuity
from utils.common import logger, credentials, config
from utils.pki import pubkey_to_addr
from queue import Queue, PriorityQueue
import copy


class Clockchain(object):
    def __init__(self):
        self.chain = Queue(maxsize=config['chain_max_length'])
        self.ping_pool = {}
        # Priority queue because we want to sort by cumulative continuity
        self.tick_pool = PriorityQueue()

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

    def possible_previous_ticks(self):
        return self.chainlist()[-1]

    def chainlist(self):
        return list(self.chain.queue)

    def restart_cycle(self):
        self.ping_pool = {}
        self.tick_pool = {}

    def add_to_ping_pool(self, ping):
        addr_to_add = pubkey_to_addr(ping['pubkey'])
        self.ping_pool[addr_to_add] = ping

    def add_to_tick_pool(self, tick):
        tick_copy = copy.deepcopy(tick)

        # Make sure the first tick received becomes the active tick
        if len(list(self.tick_pool.queue)) == 0:
            self.active_tick = tick_copy

        tick_continuity = measure_tick_continuity(tick_copy, self.chainlist())

        # Putting minus sign on the continuity measurement since PriorityQueue
        # Returns the *lowest* valued item first, while we want *highest*
        self.tick_pool.put((-tick_continuity, tick_copy))

    def current_highest_tick_ref(self):
        _, tick = list(self.tick_pool.queue)[0]
        return tick['this_tick']

    def consolidate_ticks_to_chain(self):
        # Get highest cumulative continuity tick
        tick_dict = {}

        highest_score, highest_tick = self.tick_pool.get_nowait()

        highest_tick_copy = copy.deepcopy(highest_tick)

        highest_tick_ref = highest_tick_copy.pop('this_tick', None)
        if highest_tick_ref is not None:
            tick_dict[highest_tick_ref] = highest_tick_copy

        # Add all ticks which achieved same continuity to the dictionary
        # WARNING: This MUST happen less than 50% of the time and result in
        # usually only 1 winner, so chain only branches occasionally
        # and thus doesn't become an exponentially growing tree.
        # This is the main condition to achieve network-wide consensus
        next_highest_score, next_highest_tick = self.tick_pool.get_nowait()
        while highest_score == next_highest_score:
            next_copy = copy.deepcopy(next_highest_tick)
            next_tick_ref = next_copy.pop('this_tick', None)
            if next_tick_ref is not None:
                tick_dict[next_tick_ref] = next_copy

            next_highest_score, next_highest_tick = self.tick_pool.get_nowait()

        if self.chain.full():
            # This removes earliest item from queue
            self.chain.get_nowait()

        self.chain.put(tick_dict)
        self.restart_cycle()

