from utils.validation import validate_ping
from utils.helpers import utcnow, standard_encode, mine, logger
from utils.pki import pubkey_to_addr, sign
import threading


class Timeminer(object):
    def __init__(self, messages, clockchain):
        self.clockchain = clockchain
        self.messages = messages

        self.added_ping = False
        logger.debug("This node is " + self.clockchain.addr)

        # TODO: Figure out how to decide common genesis tick if diff starthash
        # TODO: Re-adapt this to use signatures
        genesis_addr = "tempigFUe1uuRsAQ7WWNpb5r97pDCJ3wp9"
        self.clockchain.chain.append(
            {'addr': genesis_addr, 'nonce': 27033568337, 'list': []})

        self.ping_thread = threading.Thread(target=self.ping_worker)
        self.tick_thread = threading.Thread(target=self.tick_worker)
        self.ping_thread.start()
        self.tick_thread.start()

    def ping_worker(self):
        while True:
            if not self.added_ping:
                logger.debug("Havent pinged this round! Starting to mine..")
                ping = {'pubkey': self.clockchain.pubkey,
                        'timestamp': utcnow(),
                        'reference': self.clockchain.current_tick_ref()}

                # Always do mining and put nonce after ping construction
                # but before inserting signature
                _, nonce = mine(ping)
                ping['nonce'] = nonce

                signature = sign(standard_encode(ping), self.clockchain.privkey)
                ping['signature'] = signature

                # Validate own ping
                if not validate_ping(ping, self.clockchain.pingpool,
                                     check_in_pool=True):
                    logger.debug("Failed own ping validation")
                    continue  # Skip to next iteration of while loop

                # Add to pool
                addr = pubkey_to_addr(ping['pubkey'])
                self.clockchain.pingpool[addr] = ping
                self.added_ping = True

                # Forward to peers (this must be at end after all validation)
                self.messages.put(ping)

                logger.debug("Forwarded own ping: " + str(ping))

    # TODO: Consensus mechanism
    def tick_worker(self):
        while True:
            if self.added_ping:
                pass
