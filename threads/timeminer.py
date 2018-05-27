from utils.validation import validate_ping, validate_tick
from utils.helpers import utcnow, standard_encode, mine
from utils.common import logger, credentials, config
from utils.pki import sign
import time
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
        if not validate_ping(ping, self.clockchain.ping_pool,
                             vote, self.clockchain.vote_pool):
            logger.debug("Failed own ping validation")
            return False

        if vote:
            self.clockchain.add_to_vote_pool(ping)
        else:
            self.clockchain.add_to_ping_pool(ping)

        # Forward to peers (this must be after all validation)
        self.networker.forward(data_dict=ping, route='ping',
                               origin=credentials.addr,
                               redistribute=0)

        logger.debug("Forwarded own ping: " + str(ping))

        return True

    def generate_and_process_tick(self):
        # Here we already have active tick, so no point in sending own
        if self.clockchain.tick_already_chosen():
            logger.debug("Already chosen at tick start")
            return False

        height = self.clockchain.current_height() + 1

        tick = {
            'list': list(self.clockchain.ping_pool.values()),
            'pubkey': credentials.pubkey,
            'prev_tick': self.clockchain.current_tick_ref(),
            'height': height
        }

        this_tick, nonce = mine(tick)

        if self.clockchain.tick_already_chosen():
            logger.debug("Already chosen after mining")
            return False

        tick['nonce'] = nonce

        signature = sign(standard_encode(tick), credentials.privkey)
        tick['signature'] = signature

        # This is to keep track of the "name" of the tick as debug info
        # this_tick is not actually necessary according to tick schema
        tick['this_tick'] = this_tick

        current_height = self.clockchain.current_height()

        possible_previous = self.clockchain.possible_previous_ticks()

        # Validate own tick
        if not validate_tick(tick, current_height, possible_previous):
            logger.debug("Failed own tick validation")
            return False

        if self.clockchain.tick_already_chosen():
            logger.debug("Already chosen after validation")
            return False

        self.clockchain.add_to_tick_pool(tick)

        # Forward to peers (this must be after all validation)
        self.networker.forward(data_dict=tick, route='tick',
                               origin=credentials.addr,
                               redistribute=0)

        logger.debug("Forwarded own tick: " + str(tick))

        return True

    def ping_worker(self):
        while True:
            if self.networker.ready and not self.added_ping:

                logger.debug("Haven't pinged this round! Starting to mine..")
                successful = \
                    self.generate_and_process_ping(
                        self.clockchain.current_tick_ref())

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

                # Adding a bit of margin for mining, otherwise tick rejected
                time.sleep(config['tick_period'] + config['tick_period_margin'])
                # TODO: Adjust margin based on max possible mining time?

                logger.debug("Haven't ticked this round! Starting to mine..")

                self.networker.stage = "init"

                self.generate_and_process_tick()

                time.sleep(config['tick_step_time'])

                logger.debug("Voting stage------------------------------")
                self.networker.stage = "vote"
                # Use a ping to vote for highest continuity tick in tick_pool

                active_tick_ref = self.clockchain.active_tick()['this_tick']

                self.generate_and_process_ping(active_tick_ref, vote=True)

                logger.debug("Voted for: " + str(active_tick_ref))

                time.sleep(config['tick_step_time'])

                logger.debug("Consolidate ticks stage-------------------------")
                self.networker.stage = "consolidate"

                self.clockchain.consolidate_highest_voted_to_chain()

                self.added_ping = False
            else:
                time.sleep(1)
