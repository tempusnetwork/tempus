from utils.helpers import hasher, measure_tick_continuity, mine
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
        tick = {
            'pubkey': 'pubkey',
            'nonce': 68696043434,
            'list': [],
            'prev_tick': 'prev_tick',
            'height': 0,
            'this_tick': '5ecb6e893a9350bed889b88a1fd04e58'
                         'e6d173a7592586547f8a658c2a160000'
        }

        self.active_tick = tick
        genesis_dict = self.dictify(self.active_tick)
        self.chain.put(genesis_dict)

    def current_tick_ref(self):
        last_block_copy = copy.deepcopy(self.active_tick)

        # Removing signature and this_tick in order to return correct hash
        last_block_copy.pop('signature', None)
        last_block_copy.pop('this_tick', None)

        return hasher(last_block_copy)

    def dictify(self, tick):
        dictified = {}

        tick_copy = copy.deepcopy(tick)
        tick_ref = tick_copy.pop('this_tick', None)
        if tick_ref is not None:
            dictified[tick_ref] = tick_copy
        else:
            # TODO: Create the ref from scratch if it wasn't found in dict
            pass

        return dictified

    def current_height(self):
        return self.active_tick['height']

    def possible_previous_ticks(self):
        if len(self.chainlist()) > 0:
            return self.chainlist()[-1]
        else:
            return None

    def chainlist(self):
        return list(self.chain.queue)

    def restart_cycle(self):
        self.ping_pool = {}
        self.tick_pool = PriorityQueue()

    def tick_already_chosen(self):
        if len(list(self.tick_pool.queue)) == 0:
            return False
        else:
            return True

    def add_to_ping_pool(self, ping):
        addr_to_add = pubkey_to_addr(ping['pubkey'])
        self.ping_pool[addr_to_add] = ping

    def add_to_tick_pool(self, tick):
        tick_copy = copy.deepcopy(tick)

        # Make sure the first received tick becomes the active tick
        if not self.tick_already_chosen():
            self.active_tick = tick_copy

        tick_continuity = measure_tick_continuity(self.dictify(tick_copy)
                                                  , self.chainlist())

        # Putting minus sign on the continuity measurement since PriorityQueue
        # Returns the *lowest* valued item first, while we want *highest*
        self.tick_pool.put((-tick_continuity, tick_copy))

    def current_highest_tick_ref(self):
        _, tick = list(self.tick_pool.queue)[0]
        return tick['this_tick']

    def consolidate_ticks_to_chain(self):
        # Get highest cumulative continuity tick
        highest_score, highest_tick = self.tick_pool.get()

        tick_dict = self.dictify(highest_tick)

        # ---- Add all ticks with same continuity values to the dictionary ----
        # WARNING: This MUST happen less than 50% of the time and result in
        # usually only 1 winner, so that chain only branches occasionally
        # and thus doesn't become an exponentially growing tree.
        # This is the main condition to achieve network-wide consensus
        if not self.tick_pool.empty():
            next_highest_score, next_highest_tick = self.tick_pool.get()
        else:
            next_highest_score, next_highest_tick = (float('nan'), {})

        while highest_score == next_highest_score and not self.tick_pool.empty():
            dict_to_add = self.dictify(next_highest_tick)
            tick_dict = {**tick_dict, **dict_to_add}  # Merging dictionaries

            next_highest_score, next_highest_tick = self.tick_pool.get()

        if self.chain.full():
            # This removes earliest item from queue
            self.chain.get()

        self.chain.put(tick_dict)
        self.restart_cycle()

