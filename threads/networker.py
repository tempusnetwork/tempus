import json
import time
import random
import requests

from utils.pki import sign
from threading import Timer, Thread
from urllib.parse import urlparse

from utils.common import logger, config, credentials
from utils.helpers import standard_encode, handle_exception


class Networker(object):
    def __init__(self):

        self.peers = {}
        self.port = 0
        self.ready = False
        self.block_ticks = False
        self.join_network_thread = Thread(target=self.join_network_worker)
        # Timer for activation thread (uses resettable timer to find out port)
        self.t = Timer(config['port_timer_timeout'], self.activate)

    def activate(self):
        self.join_network_thread.start()

    def set_port(self, port):
        # This timer start and resetting necessary to get the correct port..
        # I.e. if port is blocked, this method gets called again until timer
        # is allowed to finally elapse and start the join network thread
        self.t.cancel()
        self.t = Timer(config['port_timer_timeout'], self.activate)
        self.port = port
        logger.debug("Trying port " + str(self.port))
        self.t.start()

    def register_peer(self, url, peer_addr):
        """
        Add a new peer to the list of peers

        :param url: <str> Address of peer. Eg. 'http://192.168.0.5:5000'
        :param peer_addr: <str> Mining addr of peer
        :return: <bool> Whether it was already in list or not
        """
        netloc = urlparse(url).netloc

        netloc = "http://" + netloc

        # Avoid adding self
        if peer_addr == credentials.addr:
            return False

        # Avoid adding already existing netloc
        if netloc in self.peers:
            return False

        self.peers[netloc] = peer_addr
        return True

    def forward(self, data_dict, route, origin=None, redistribute=0):
        """
        Forward any json content to another peer

        :param data_dict: dictionary which becomes json content
        :param route: which route it's addressed at
            (for ex, forwarding a txn, a peer, etc)
        :param origin: origin of this forward
        :param redistribute: Amount of hops (redistributions through peers)
            this json message has passed through
        :return: void
        """
        # TODO: Right now max hops is set to 1.... meaning no redistribution.
        # Good cause we have full netw connectivity
        # TODO: However for nonfully connected nodes, > 1 hops needed to fully
        # reach all corners and nodes of network

        # Dont forward to peers if exceeding certain amount of hops
        if redistribute < config['max_hops']:
            # TODO: What happens if malicious actor fakes the ?addr= ?? or the
            # amount of hops?
            for peer in self.peers:
                try:  # Add self.addr in query to identify self to peers
                    # If origin addr is not target peer addr
                    if origin != self.peers[peer]:
                        redistribute = redistribute + 1
                        requests.post(
                            peer + '/forward/' + route + '?addr=' + origin +
                            "&redistribute=" + str(redistribute),
                            json=data_dict, timeout=config['timeout'])

                except Exception as e:
                    handle_exception(e)
                    pass

    def unregister_peer(self, url):
        netloc = urlparse(url).netloc
        del self.peers[netloc]

    def send_mutual_add_requests(self, peerslist, get_further_peers=False):
        # Preparing a set of further peers to possibly add later on
        peers_of_peers = set()

        # Mutual add peers
        for peer in peerslist:
            if peer not in self.peers:
                content = {"port": self.port, 'pubkey': credentials.pubkey}
                signature = sign(standard_encode(content),
                                 credentials.privkey)
                content['signature'] = signature
                try:
                    response = requests.post(
                        peer + '/mutual_add',
                        json=content,
                        timeout=config['timeout'])

                    status_code = response.status_code
                    logger.info("Status for peer adding: " + str(status_code))
                except Exception as e:
                    handle_exception(e)
                    continue
                if status_code == 201:
                    logger.info("Adding peer " + str(peer))
                    peer_addr = response.text
                    self.register_peer(peer, peer_addr)

                    # Get all peers of current discovered peers and add to set
                    # (set is to avoid duplicates)
                    # Essentially going one degree further out in network. From
                    # current peers to their peers
                    if get_further_peers:
                        next_peers = json.loads(
                            requests.get(peer + '/info/peers').text)
                        for next_peer in next_peers['peers']:
                            peers_of_peers.add(next_peer)

        return list(peers_of_peers)

    def join_network_worker(self):
        # Sleeping random amount to not have seed-clash (cannot do circular
        #  adding of peers at the exact same time as seeds)
        sleeptime = 2 + random.randrange(3000) / 1000.0
        logger.debug("Sleeping for " + str(sleeptime) + "s before network join")
        time.sleep(sleeptime)

        # First add seeds, and get the seeds peers
        peers_of_seeds = self.send_mutual_add_requests(
            config['seeds'], get_further_peers=True)

        # Then add the peers of seeds
        # TODO: Have seeds only return max 8 randomly chosen peers?
        self.send_mutual_add_requests(peers_of_seeds)

        logger.debug("Peers: " + str(self.peers))

        # TODO: Sync latest datastructures with peers (choosing the majority?)
        logger.debug("Finished joining network")
        self.ready = True
