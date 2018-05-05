from utils.validation import validate_ping
from utils.helpers import utcnow, standard_encode, mine
from utils.common import logger, credentials
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
            if self.networker.ready:
                if not self.added_ping:
                    logger.debug("Havent pinged this round! Starting to mine..")
                    ping = {'pubkey': credentials.pubkey,
                            'timestamp': utcnow(),
                            'reference': self.clockchain.current_tick_ref()}

                    # Always do mining and put nonce after ping construction
                    # but before inserting signature
                    _, nonce = mine(ping)
                    ping['nonce'] = nonce

                    signature = sign(standard_encode(ping), credentials.privkey)
                    ping['signature'] = signature

                    # Validate own ping
                    if not validate_ping(ping, self.clockchain.ping_pool,
                                         check_in_pool=True):
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

    # TODO: Consensus mechanism
    def tick_worker(self):
        while True:
            if self.networker.ready:
                if self.added_ping:
                    pass
            else:
                time.sleep(1)
