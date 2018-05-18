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

    def generate_and_process_ping(self, reference):
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
        if not validate_ping(ping, self.clockchain.ping_pool):
            logger.debug("Failed own ping validation")
            return False

        # Add to pool
        self.clockchain.add_to_ping_pool(ping)

        # Forward to peers (this must be after all validation)
        self.networker.forward(data_dict=ping, route='ping',
                               origin=credentials.addr,
                               redistribute=0)

        logger.debug("Forwarded own ping: " + str(ping))

        return True

    def generate_and_process_tick(self, reissue=False):
        tick = {
            'list': list(self.clockchain.ping_pool.values()),
            'pubkey': credentials.pubkey,
            'prev_tick': self.clockchain.current_tick_ref(),
            'height': self.clockchain.active_tick['height']
        }

        this_tick, nonce = mine(tick)

        if self.clockchain.tick_already_chosen() and not reissue:
            return False

        tick['nonce'] = nonce

        signature = sign(standard_encode(tick), credentials.privkey)
        tick['signature'] = signature

        # This is to keep track of the "name" of the tick as debug info
        # this_tick is not actually necessary according to tick schema
        tick['this_tick'] = this_tick

        # Validate own tick
        active_tick = self.clockchain.active_tick
        possible_previous = self.clockchain.possible_previous_ticks()
        if reissue:
            active_tick = None
            possible_previous = None

        if not validate_tick(tick, active_tick, possible_previous):
            logger.debug("Failed own tick validation")
            return False

        if self.clockchain.tick_already_chosen() and not reissue:
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

                self.networker.block_ticks = False

                # Here we already have active tick, so no point in sending own
                if self.clockchain.tick_already_chosen():
                    continue

                if not self.generate_and_process_tick():
                    continue

                time.sleep(config['tick_step_time'])

                # Reissue a ping for highest continuity tick in tick_pool
                self.generate_and_process_ping(
                    self.clockchain.current_highest_tick_ref())

                time.sleep(config['tick_step_time'])

                self.generate_and_process_tick(reissue=True)

                time.sleep(config['tick_step_time'])

                self.networker.block_ticks = True

                self.clockchain.consolidate_ticks_to_chain()

                self.added_ping = False
            else:
                time.sleep(1)
