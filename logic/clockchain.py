import time
import threading
from utils.pki import pubkey_to_addr, sign, get_kp
from utils.helpers import utcnow, standard_encode, hasher, mine, logger
from utils.validation import validate_ping


class Clockchain(object):
    def __init__(self, messenger, privkey):
        self.privkey = privkey
        self.pubkey, _ = get_kp(privkey=self.privkey)
        self.addr = pubkey_to_addr(self.pubkey)

        self.chain = []
        self.pingpool = {}
        self.added_ping = False
        self.messenger = messenger

        logger.debug("This node is " + self.addr)

        # TODO: Figure out how to decide common genesis
        # tick if all start with diff hashes..
        # Create genesis tick
        # TODO: Re-adapt this to use signatures
        genesis_addr = "tempigFUe1uuRsAQ7WWNpb5r97pDCJ3wp9"
        self.chain.append(
            {'addr': genesis_addr, 'nonce': 27033568337, 'list': []})

        self.ping_thread = threading.Thread(target=self.ping_worker)
        self.tick_thread = threading.Thread(target=self.tick_worker)
        self.ping_thread.start()
        self.tick_thread.start()

    def current_tick_ref(self):
        return hasher(self.chain[-1])

    def restart_tick(self):
        self.added_ping = False
        self.pingpool = {}

    def ping_worker(self):
        while True:
            time.sleep(20)
            if not self.added_ping:
                logger.debug("Havent pinged this round! Starting to mine..")
                ping = {'pubkey': self.pubkey,
                        'timestamp': utcnow(),
                        'reference': self.current_tick_ref()}

                # Always do mining and put nonce after ping construction
                # but before inserting signature
                _, nonce = mine(ping)
                ping['nonce'] = nonce

                signature = sign(standard_encode(ping), self.privkey)
                ping['signature'] = signature

                # Validate own ping
                if not validate_ping(ping, self.pingpool, check_in_pool=True):
                    logger.debug("Failed own ping validation")
                    continue  # Skip to next iteration of while loop

                # Add to pool
                addr = pubkey_to_addr(ping['pubkey'])
                self.pingpool[addr] = ping
                self.added_ping = True

                # Forward to peers (this must be at end after all validation)
                self.messenger.forward(ping, 'ping', self.addr)
                logger.debug("Forwarded own ping: " + str(ping))

    # TODO: Consensus mechanism
    def tick_worker(self):
        while True:
            if self.added_ping:
                pass
