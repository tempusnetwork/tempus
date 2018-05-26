from utils.helpers import hasher, measure_tick_continuity
from utils.common import logger, credentials, config
from utils.pki import pubkey_to_addr
from queue import Queue, PriorityQueue
import copy


class Clockchain(object):
    def __init__(self):
        self.chain = Queue(maxsize=config['chain_max_length'])
        self.ping_pool = {}
        self.vote_pool = {}
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

        genesis_dict = self.json_tick_to_chain_tick(tick)
        self.chain.put(genesis_dict)

    def current_tick_ref(self):
        current_tick_copy = copy.deepcopy(self.active_tick())

        # Removing signature and this_tick in order to return correct hash
        current_tick_copy.pop('signature', None)
        current_tick_copy.pop('this_tick', None)

        return hasher(current_tick_copy)

    def json_tick_to_chain_tick(self, tick):
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
        return self.active_tick()['height']

    def possible_previous_ticks(self):
        if len(self.chainlist()) > 0:
            return self.chainlist()[-1]
        else:
            return None

    def chainlist(self):
        return list(self.chain.queue)

    def restart_cycle(self):
        self.ping_pool = {}
        self.vote_pool = {}
        self.tick_pool = PriorityQueue()

    def tick_pool_size(self):
        return len(list(self.tick_pool.queue))

    def tick_already_chosen(self):
        if self.tick_pool_size() == 0:
            return False
        else:
            return True

    def add_to_ping_pool(self, ping):
        addr_to_add = pubkey_to_addr(ping['pubkey'])
        self.ping_pool[addr_to_add] = ping

    def add_to_vote_pool(self, vote):
        ref_to_vote_on = vote['reference']
        if ref_to_vote_on in self.vote_pool:
            self.vote_pool[ref_to_vote_on] = self.vote_pool[ref_to_vote_on] + 1
        else:
            self.vote_pool[ref_to_vote_on] = 1

    def add_to_tick_pool(self, tick):
        tick_copy = copy.deepcopy(tick)

        tick_continuity = measure_tick_continuity(
            self.json_tick_to_chain_tick(tick_copy), self.chainlist())

        # Using tick number to insert into PriorityQueue, this allows for
        # "Stable sorting" of equal valued priorities (FIFO)
        # This guarantees that the top item is first sorted by Priority,
        # and then by insertion order
        tick_number = self.tick_pool_size() + 1

        # Putting minus sign on the continuity measurement since PriorityQueue
        # Returns the *lowest* valued item first, while we want *highest*
        self.tick_pool.put((-tick_continuity, tick_number, tick_copy))

    # Return highest voted ticks (several if shared top score)
    def top_tick_refs(self):
        highest_voted_ticks = []

        # Sort by value (amount of votes)
        sorted_votes = sorted(self.vote_pool.items(), key=lambda x: x[1],
                              reverse=True)

        top_ref, top_score = sorted_votes.pop(0)
        highest_voted_ticks.append(top_ref)

        for vote in sorted_votes:
            next_ref, next_score = vote
            if next_score == top_score:
                highest_voted_ticks.append(next_ref)
            else:
                break

        return highest_voted_ticks

    def get_ticks_by_ref(self, references):
        # Get the actual tick (index 2) from the tuple (_, _, tick)
        # And put it in a list
        list_of_all_ticks = [x[2] for x in list(self.tick_pool.queue)]

        # Return list of all ticks whose ref matches supplied ref
        filtered_ticks = [tick for tick in list_of_all_ticks if
                          tick['this_tick'] in references]

        return filtered_ticks

    def active_tick(self):
        # This will be the lowest score (highest cumulative cont.)
        if self.tick_pool_size() > 0:
            _, _, tick = list(self.tick_pool.queue)[0]
        else:
            # Choose at random
            tick = next(iter(self.possible_previous_ticks().values()))
        return tick

    def consolidate_highest_voted_to_chain(self):
        # ---- Add all ticks with same amount of votes to the dictionary ----
        # WARNING: This MUST happen less than 50% of the time and result in
        # usually only 1 winner, so that chain only branches occasionally
        # and thus doesn't become an exponentially growing tree.
        # This is the main condition to achieve network-wide consensus
        highest_ticks = self.get_ticks_by_ref(self.top_tick_refs())

        tick_dict = {}
        for tick in highest_ticks:
            to_add = self.json_tick_to_chain_tick(tick)
            tick_dict = {**tick_dict, **to_add}

        if self.chain.full():
            # This removes earliest item from queue
            self.chain.get()

        self.chain.put(tick_dict)
        self.restart_cycle()
