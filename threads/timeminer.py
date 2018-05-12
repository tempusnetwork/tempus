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

    def ping_worker(self):
        while True:
            if self.networker.ready and not self.added_ping:
                # Always construct ping in the following order:
                # 1) Init 2) Mine+nonce 3) Add signature
                # This is because the order of nonce and sig creation matters

                logger.debug("Havent pinged this round! Starting to mine..")
                ping = {'pubkey': credentials.pubkey,
                        'timestamp': utcnow(),
                        'reference': self.clockchain.current_tick_ref()}

                _, nonce = mine(ping)
                ping['nonce'] = nonce

                signature = sign(standard_encode(ping), credentials.privkey)
                ping['signature'] = signature

                # Validate own ping
                if not validate_ping(ping, self.clockchain.ping_pool):
                    logger.debug("Failed own ping validation")
                    continue  # Skip to next iteration of while loop

                # Add to pool
                self.clockchain.ping_pool[credentials.addr] = ping
                self.added_ping = True

                # Forward to peers (this must be after all validation)
                self.networker.forward(data_dict=ping, route='ping',
                                       origin=credentials.addr,
                                       redistribute=0)

                logger.debug("Forwarded own ping: " + str(ping))
            else:
                time.sleep(1)

    def tick_worker(self):
        while True:
            if self.networker.ready and self.added_ping:
                # Always construct tick in the following order:
                # 1) Init 2) Mine+nonce 3) Add signature
                # This is because the order of nonce and sig creation matters

                # Adding a bit of margin for mining, otherwise tick rejected
                # TODO: Adjust margin based on max possible mining time?
                time.sleep(config['tick_period'] + config['tick_period_margin'])

                logger.debug("Havent ticked this round! Starting to mine..")

                if len(list(self.clockchain.ping_pool.values())) < 1:
                    logger.debug("Tried mining empty ping_pool, "
                                 "someone else probably found solution")
                    continue

                tick = {
                    'list': list(self.clockchain.ping_pool.values()),
                    'pubkey': credentials.pubkey,
                    'prev_tick': self.clockchain.current_tick_ref()
                }

                this_tick, nonce = mine(tick)
                tick['nonce'] = nonce

                signature = sign(standard_encode(tick), credentials.privkey)
                tick['signature'] = signature

                # This is to keep track of the "name" of the tick as debug info
                # this_tick is not actually necessary according to tick schema
                tick['this_tick'] = this_tick

                # Validate own tick
                if not validate_tick(tick):
                    logger.debug("Failed own tick validation")
                    # TODO: Change self.added_ping to false here?
                    continue  # Skip to next iteration of while loop

                # Add to own chain and restart ping collecting

                self.clockchain.add_tick(tick)
                self.clockchain.restart_tick()

                # Forward to peers (this must be after all validation)
                self.networker.forward(data_dict=tick, route='tick',
                                       origin=credentials.addr,
                                       redistribute=0)

                logger.debug("Forwarded own tick: " + str(tick))
                self.added_ping = False
            else:
                time.sleep(1)
