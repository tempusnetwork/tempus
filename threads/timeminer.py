from utils.validation import validate_ping, validate_tick
from utils.helpers import utcnow, standard_encode, mine, median_ts
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

        stage = 'vote' if vote else 'ping'

        _, nonce = mine(ping)
        ping['nonce'] = nonce

        signature = sign(standard_encode(ping), credentials.privkey)
        ping['signature'] = signature

        # Validate own ping
        if not validate_ping(ping, self.clockchain.ping_pool, vote):
            logger.debug("Failed own " + stage + " validation")
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

        prev_tick = self.clockchain.latest_selected_tick()

        possible_previous = self.clockchain.possible_previous_ticks()

        # Validate own tick
        retries = 0
        while retries < config['tick_retries']:
            if not validate_tick(tick, prev_tick, possible_previous,
                                 verbose=False):
                retries = retries + 1
                time.sleep(config['tick_retries_sleep'])
            else:
                self.clockchain.add_to_tick_pool(tick)
                # Forward to peers (this must be after all validation)
                self.networker.forward(data_dict=tick, route='tick',
                                       origin=credentials.addr,
                                       redistribute=0)
                logger.debug("Forwarded own tick: " + str(tick))
                return True

        logger.debug("Failed own tick validation too many times. not forwarded")
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
                cycle_time = config['cycle_time']
                cycle_multiplier = config['cycle_time_multiplier']

                # Dynamic adjusting of sleeping time to match network lockstep
                prev_tick_ts = median_ts(self.clockchain.latest_selected_tick())
                desired_ts = prev_tick_ts + cycle_multiplier*cycle_time

                wait_time = desired_ts - utcnow()

                logger.debug("Median ts: " + str(prev_tick_ts) + " min ts: "
                             + str(desired_ts) + " curr ts: " + str(utcnow()))

                overshoot = 0

                if wait_time < 0:
                    if self.clockchain.current_height() != 0:  # If init, ignore
                        overshoot = -wait_time
                    logger.debug("Overshoot of " + str(int(overshoot)) + "s")
                    wait_time = 0

                logger.debug("Adjusted sleeping time: " + str(int(wait_time)))
                time.sleep(wait_time)  # Adjusting to follow network timing

                logger.debug("Tick stage--------------------------------------")
                start = time.time()  # Start and end time used to adjust sleep

                self.networker.stage = "tick"

                self.generate_and_process_tick()

                # All in all, there should be a total sleep of
                # 'cycle_time_multiplier' * 'cycle_time' in this thread.
                # Gets adjusted dynamically by wait_time mechanism above
                end = time.time()

                # Overshoot is used if we slept too long in ping stage,
                # then we compensate in this tick stage by speeding up sleep
                second_sleep = cycle_time - (end-start) - overshoot
                second_sleep = 0 if second_sleep < 0 else second_sleep

                time.sleep(second_sleep)  # 2nd sleep

                logger.debug("Vote stage--------------------------------------")
                start = time.time()

                self.networker.stage = "vote"
                # Use a ping to vote for highest continuity tick in tick_pool

                # TODO: What happens if I just selfishly vote for my own tick?
                active_tick_ref = self.clockchain.current_tick_ref()

                self.generate_and_process_ping(active_tick_ref, vote=True)

                logger.debug("Voted for: " + str(active_tick_ref))

                end = time.time()

                inbetween_sleep = cycle_time / 2
                time.sleep(inbetween_sleep)  # 2.5th sleep

                # Clearing ping_pool here already to possibly receive new pings
                self.clockchain.ping_pool = {}

                third_sleep = cycle_time - inbetween_sleep - (end-start)
                third_sleep = 0 if third_sleep < 0 else third_sleep
                time.sleep(third_sleep)  # 3rd sleep

                logger.debug("Select ticks stage------------------------------")
                self.networker.stage = "select"

                self.clockchain.select_highest_voted_to_chain()
                # TODO: If nothing was added to chain.. sth obv. wrong! Resync?

                self.added_ping = False
            else:
                time.sleep(1)
