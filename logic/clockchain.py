import threading
import time

from utils.pki import pubkey_to_addr, get_kp
from utils.helpers import hasher, logger


class Clockchain(object):
    def __init__(self, privkey):
        self.privkey = privkey
        self.pubkey, _ = get_kp(privkey=self.privkey)
        self.addr = pubkey_to_addr(self.pubkey)

        self.chain = []
        self.pingpool = {}
        self.added_ping = False

        logger.debug("This node is " + self.addr)

        # TODO: Figure out how to decide common genesis tick if diff starthash
        # TODO: Re-adapt this to use signatures
        genesis_addr = "tempigFUe1uuRsAQ7WWNpb5r97pDCJ3wp9"
        self.chain.append(
            {'addr': genesis_addr, 'nonce': 27033568337, 'list': []})

        self.ping_thread = threading.Thread(target=self.ping_worker)
        self.tick_thread = threading.Thread(target=self.tick_worker)
        self.activation_thread = threading.Thread(target=self.activate)
        self.activation_thread.start()

    def activate(self):
        # TODO: Remove tight coupling below between clockchain and messenger
        # This is a bit of an ugly hack to check whether the messenger is done
        # with connecting to his peers, before starting the clockchain processes
        # This control should be done by main.py
        while True:
            time.sleep(1)
            if self.messenger.ready:
                self.ping_thread.start()
                self.tick_thread.start()
                break
            else:
                continue

    def current_tick_ref(self):
        return hasher(self.chain[-1])

    def restart_tick(self):
        self.added_ping = False
        self.pingpool = {}