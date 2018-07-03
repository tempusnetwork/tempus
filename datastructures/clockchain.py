from utils.helpers import hasher, measure_tick_continuity
from utils.common import logger, credentials, config
from utils.pki import pubkey_to_addr
from queue import Queue, PriorityQueue
import copy
import time


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
            'list': [
                {'timestamp': 0, 'pubkey': 'pubkey'}
            ],
            'prev_tick': 'prev_tick',
            'height': 0,
            'this_tick': '55f5b323471532d860b11d4fc079ba38'
                         '819567aa0915d83d4636d12e498a8f3e'
        }

        genesis_dict = self.json_tick_to_chain_tick(tick)
        self.chain.put(genesis_dict)

    # Returns most recent tick reference: highest continuity tick from tickpool
    # Used for voting
    def current_tick_ref(self):
        while self.active_tick() is None:
            time.sleep(0.1)
        return self.get_tick_ref(self.active_tick())

    # Returns the reference of any of previous ticks that was selected to chain
    def prev_tick_ref(self):
        return self.get_tick_ref(self.latest_selected_tick())

    # Helper function to get the reference of a tick
    @staticmethod
    def get_tick_ref(tick):
        tick_copy = copy.deepcopy(tick)

        # Removing signature and this_tick in order to return correct hash
        tick_copy.pop('signature', None)
        tick_copy.pop('this_tick', None)

        return hasher(tick_copy)

    # Helper function to convert a json tick to a tick format used in our chain
    # Essentially instead of having a tick with its reference in ['this_tick'],
    # it uses the reference as dictionary key for fast retrieval of rest of tick
    @staticmethod
    def json_tick_to_chain_tick(tick):
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
        return self.latest_selected_tick()['height']

    # Returns the current highest continuity tick from tick_pool
    def active_tick(self):
        if self.tick_pool_size() > 0:
            _, _, tick = list(self.tick_pool.queue)[0]
            return tick
        else:
            return None

    # Named possible since the chain might have orphans / be forked
    def possible_previous_ticks(self):
        if len(self.chainlist()) > 0:
            return self.chainlist()[-1]
        else:
            return None

    def chainlist(self):
        return list(self.chain.queue)

    def restart_cycle(self):
        # Ping_pool is not cleared here since we might have received pings
        # at vote/select stage already, by faster peers
        self.vote_pool = {}
        self.tick_pool = PriorityQueue()

    def tick_pool_size(self):
        return len(list(self.tick_pool.queue))

    def add_to_ping_pool(self, ping):
        addr_to_add = pubkey_to_addr(ping['pubkey'])
        self.ping_pool[addr_to_add] = ping

    # Different to above: only store the vote reference and not entire structure
    def add_to_vote_pool(self, vote):
        addr_to_add = pubkey_to_addr(vote['pubkey'])
        self.vote_pool[addr_to_add] = vote['reference']

    # Returns a dict where keys are references of ticks and their nr of votes
    def get_vote_counts(self):
        count_dict = {}

        for k, v in self.vote_pool.items():
            if v in count_dict.keys():
                count_dict[v] = count_dict[v] + 1
            else:
                count_dict[v] = 1

        return count_dict

    def add_to_tick_pool(self, tick):
        tick_copy = copy.deepcopy(tick)

        tick_continuity = measure_tick_continuity(
            self.json_tick_to_chain_tick(tick_copy), self.chainlist())

        # This tracking number is used to make sure that in the case of
        # equal valued items, the first one (FIFO) is returned. tick_number
        # simply keeps track of which equivalued tick was inserted first
        tick_number = self.tick_pool_size() + 1

        # Putting minus sign on the continuity measurement since PriorityQueue
        # Returns the *lowest* valued item first, while we want *highest*
        self.tick_pool.put((-tick_continuity, tick_number, tick_copy))

    # Return highest voted ticks (several if shared top score)
    def top_tick_refs(self):
        highest_voted_ticks = []

        # Sort by value (amount of votes)
        sorted_votes = sorted(self.get_vote_counts().items(),
                              key=lambda x: x[1], reverse=True)

        top_ref, top_score = sorted_votes.pop(0)
        highest_voted_ticks.append(top_ref)

        logger.debug("Highest amount of votes achieved was: " + str(top_score))

        # If any other refs share the same score, we return those too
        for vote in sorted_votes:
            next_ref, next_score = vote
            if next_score == top_score:
                highest_voted_ticks.append(next_ref)
            else:
                break

        return highest_voted_ticks

    def get_ticks_by_ref(self, references):
        # Get the actual tick from the tuple (_, _, tick) which is index 2
        # And put it in a list
        list_of_all_ticks = [x[2] for x in list(self.tick_pool.queue)]

        # Return list of all ticks whose ref matches supplied ref
        filtered_ticks = [tick for tick in list_of_all_ticks if
                          tick['this_tick'] in references]

        return filtered_ticks

    # Returns one of the tick possibilities (at random?)
    def latest_selected_tick(self):
        # TODO: Return the one with highest amount of pings?
        tick = None
        while tick is None:
            try:
                tick = next(iter(self.possible_previous_ticks().values()))
            except StopIteration:
                tick = None
                pass

        return tick

    def select_highest_voted_to_chain(self):
        # ---- Add all ticks with same amount of votes to the dictionary ----
        # WARNING: This MUST happen less than 50% of the time and result in
        # usually only 1 winner, so that chain only branches occasionally
        # and thus doesn't become an exponentially growing tree.
        # This is the main condition to achieve network-wide consensus
        top_tick_refs = self.top_tick_refs()

        highest_ticks = self.get_ticks_by_ref(top_tick_refs)

        # TODO: Should always be > 0 but sometimes not, when unsynced...
        if len(highest_ticks) > 0:
            logger.debug("Top tick refs with " + str(len(highest_ticks[0]['list']))
                         + " pings each:" + str(top_tick_refs))

            tick_dict = {}
            for tick in highest_ticks:
                to_add = self.json_tick_to_chain_tick(tick)
                tick_dict = {**tick_dict, **to_add}

            # TODO: Is this atomic? 
            if self.chain.full():
                # This removes earliest item from queue
                self.chain.get()

            self.chain.put(tick_dict)
        else:
            logger.info("Warning!! No ticks added to chain!!")

        self.restart_cycle()
