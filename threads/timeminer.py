from utils.validation import validate_ping, validate_tick
from utils.helpers import utcnow, standard_encode, mine
from utils.common import logger, credentials, config
from utils.pki import sign
import time
import random
import threading


class Timeminer(object):
    def __init__(self, clockchain, networker):

        self.clockchain = clockchain
        self.networker = networker
        self.added_ping = False
        self.ping_thread = threading.Thread(target=self.ping_worker)
        self.tick_thread = threading.Thread(target=self.tick_worker)
        self.ping_thread.start()
        self.tick_thread.start()

    def generate_and_process_ping(self, reference, vote=False):
        # TODO: Code duplication between here and api.. where to put??
        # TODO: Can't be in helpers, and cant be in clockchain/networker..
        # Always construct ping in the following order:
        # 1) Init 2) Mine+nonce 3) Add signature
        # This is because the order of nonce and sig creation matters

        ping = {'pubkey': credentials.pubkey,
                'timestamp': utcnow(),
                'reference': reference}

        _, nonce = mine(ping)
        ping['nonce'] = nonce

        signature = sign(standard_encode(ping), credentials.privkey)
        ping['signature'] = signature

        # Validate own ping
        if not validate_ping(ping, self.clockchain.ping_pool, vote):
            logger.debug("Failed own ping validation")
            return False

        if vote:
            self.clockchain.add_to_vote_pool(ping)
        else:
            self.clockchain.add_to_ping_pool(ping)

        route = 'vote' if vote else 'ping'

        # Forward to peers (this must be after all validation)
        self.networker.forward(data_dict=ping, route=route,
                               origin=credentials.addr,
                               redistribute=0)

        logger.debug("Forwarded own " + route + ": " + str(ping))

        return True

    def generate_and_process_tick(self):
        height = self.clockchain.current_height() + 1

        tick = {
            'list': list(self.clockchain.ping_pool.values()),
            'pubkey': credentials.pubkey,
            'prev_tick': self.clockchain.prev_tick_ref(),
            'height': height
        }

        this_tick, nonce = mine(tick)

        tick['nonce'] = nonce

        signature = sign(standard_encode(tick), credentials.privkey)
        tick['signature'] = signature

        # This is to keep track of the "name" of the tick as debug info
        # this_tick is not actually necessary according to tick schema
        tick['this_tick'] = this_tick

        current_height = self.clockchain.current_height()

        possible_previous = self.clockchain.possible_previous_ticks()

        # Validate own tick
        retries = 0
        while retries < 3:
            if not validate_tick(tick, current_height, possible_previous):
                retries = retries + 1
                time.sleep(0.5)
            else:
                self.clockchain.add_to_tick_pool(tick)
                # Forward to peers (this must be after all validation)
                self.networker.forward(data_dict=tick, route='tick',
                                       origin=credentials.addr,
                                       redistribute=0)
                logger.debug("Forwarded own tick: " + str(tick))
                return True

        logger.debug("Failed own tick validation 3 times..")
        return False

    def ping_worker(self):
        while True:
            if self.networker.ready and not self.added_ping:

                self.networker.stage = "ping"

                logger.debug("Ping stage--------------------------------------")
                successful = \
                    self.generate_and_process_ping(
                        self.clockchain.prev_tick_ref())

                if not successful:
                    continue

                self.added_ping = True
            else:
                time.sleep(1)

    def tick_worker(self):
        while True:
            # added_ping acts as a switch between "pingmode" and "tickmode"
            if self.networker.ready and self.added_ping:
                # Always construct tick in the following order:
                # 1) Init 2) Mine+nonce 3) Add signature
                # This is because the order of nonce and sig creation matters

                # TODO: Reset sleeping time to adjust to average network cycle
                # TODO: This is to make sure our own cycle doesn't drift
                # TODO: This by waiting til own.clock is exactly X seconds after
                # TODO: Previous network median timestamp, instead of sleeping
                # Adding a bit of margin for mining, otherwise tick rejected
                time.sleep(config['cycle_time']
                           + random.uniform(0, config['tick_period_margin']))

                # TODO: Adjust margin based on max possible mining time?

                logger.debug("Tick stage--------------------------------------")

                self.networker.stage = "tick"

                self.generate_and_process_tick()

                time.sleep(config['cycle_time'])

                logger.debug("Vote stage--------------------------------------")
                self.networker.stage = "vote"
                # Use a ping to vote for highest continuity tick in tick_pool

                # TODO: What happens if I just selfishly vote for my own tick?
                active_tick_ref = self.clockchain.current_tick_ref()

                self.generate_and_process_ping(active_tick_ref, vote=True)

                logger.debug("Voted for: " + str(active_tick_ref))

                time.sleep(config['cycle_time'] / 2)
                # Clearing ping_pool here already to receive new pings
                self.clockchain.ping_pool = {}
                time.sleep(config['cycle_time'] / 2)

                logger.debug("Select ticks stage------------------------------")
                self.networker.stage = "select"

                self.clockchain.select_highest_voted_to_chain()

                self.added_ping = False
            else:
                time.sleep(1)
