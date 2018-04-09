import os
import json
import sys
import logging
import requests
import threading
import random
import time
import helpers as c
from argparse import ArgumentParser
from urllib.parse import urlparse
from clockchain import Clockchain, ping_worker, tick_worker
from flask import Flask, jsonify, request
from validation import validate_tick, validate_ping, validate_schema
from pki import pubkey_to_addr, sign, verify
from helpers import remap, resolve, standard_encode, hasher
from expiringdict import ExpiringDict

logger = logging.getLogger('clocklog')


class Messenger(object):
    def __init__(self):
        self.peers = {}

        # cache to avoid processing duplicate json forwards
        self.duplicate_cache = ExpiringDict(
            max_len=c.config['expiring_dict_max_len'],
            max_age_seconds=c.config['expiring_dict_max_age'])

    def check_duplicate(self, values):
        # Check if dict values has been received in the past x seconds
        # already..
        if self.duplicate_cache.get(hasher(values)):
            return True
        else:
            self.duplicate_cache[hasher(values)] = True
            return False

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
        if peer_addr == self.addr:
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
        if redistribute < c.config['max_hops']:
            # TODO: What happens if malicious actor fakes the ?addr= ?? or the
            # amount of hops?
            for peer in self.peers:
                try:  # Add self.addr in query to identify self to peers
                    # If origin addr is not target peer addr
                    if origin != self.peers[peer]:
                        requests.post(
                            peer + '/forward/' + route + '?addr=' + origin +
                            "&redistribute=" + str(redistribute + 1),
                            json=data_dict, timeout=c.config['timeout'])
                except Exception as e:
                    logger.debug(str(sys.exc_info()))
                    pass

    def unregister_peer(self, url):
        netloc = urlparse(url).netloc
        del self.peers[netloc]


# Instantiate node
app = Flask(__name__)

# Instantiate the clockchain
messenger = Messenger()
clockchain = Clockchain(messenger)


@app.route('/forward/tick', methods=['POST'])
def forward_tick():
    tick = request.get_json()

    if messenger.check_duplicate(tick):
        return "duplicate request please wait 10s", 400

    if not validate_tick(tick):
        return "Invalid tick", 400

    clockchain.chain.append(tick)
    clockchain.restart_tick()

    # TODO: Sanitize this input..
    redistribute = int(request.args.get('redistribute'))
    if redistribute:
        origin = request.args.get('addr')
        messenger.forward(tick, 'tick', origin, redistribute=redistribute)

    return "Added tick", 201


@app.route('/forward/ping', methods=['POST'])
def forward_ping():
    ping = request.get_json()
    if messenger.check_duplicate(ping):
        return "duplicate request please wait 10s", 400

    if not validate_ping(ping, check_in_pool=True):
        return "Invalid ping", 400

    # Add to pool
    addr = pubkey_to_addr(ping['pubkey'])
    clockchain.pingpool[addr] = ping

    # TODO: Why would anyone forward others pings? Only incentivized
    # to forward own pings (to get highest uptime)
    # TODO: Would be solved if you remove peers that do not forward your pings

    redistribute = int(request.args.get('redistribute'))
    if redistribute:
        origin = request.args.get('addr')
        messenger.forward(ping, 'ping', origin, redistribute=redistribute)

    return "Added ping", 201


# TODO: In the future, create a dns seed with something similar to
# https://github.com/sipa/bitcoin-seeder
# TODO: See also
# https://bitcoin.stackexchange.com/questions/3536/
# how-do-bitcoin-clients-find-each-other/11273
@app.route('/mutual_add', methods=['POST'])
def mutual_add():
    values = request.get_json()

    # Verify json schema
    if not validate_schema(values, 'mutual_add_schema.json'):
        return "Invalid request", 400

    # Verify that pubkey and signature match
    signature = values.pop("signature")
    if not verify(standard_encode(values), signature, values['pubkey']):
        return "Invalid signature", 400

    # TODO: What if rogue peer sends fake port? Can do a ddos reflection attack?
    # TODO: Do schema validation for integer sizes / string lengths..
    remote_port = int(values.get('port'))

    remote_url = resolve(request.remote_addr)
    remote_url = "http://" + remote_url + ":" + str(remote_port)

    remote_cleaned_url = urlparse(remote_url).netloc
    own_cleaned_url = urlparse(request.url_root).netloc

    # TODO: Add sig validation here? to make sure peer is who they say they are

    # Avoid inf loop by not adding self..
    if remote_cleaned_url != own_cleaned_url:
        addr = requests.get(remote_url + '/info/addr').text

        # Verify that the host's address matches the key pair used to sign the
        # mutual_add request
        if not pubkey_to_addr(values['pubkey']) == addr:
            logger.info("Received request signed with key not matching host")
            return "Signature does not match address of provided host", 400

        if not messenger.register_peer(remote_url, addr):
            return "Could not register peer", 400
        else:  # Make sure the new joiner gets my pings (if I have any)
            if clockchain.addr in clockchain.pingpool:
                ping = clockchain.pingpool[clockchain.addr]
                # Forward but do not redistribute
                requests.post(
                    remote_url + '/forward/ping?addr=' +
                    clockchain.addr + "&redistribute=0",
                    json=ping,
                    timeout=c.config['timeout'])
    return clockchain.addr, 201


@app.route('/info/clockchain', methods=['GET'])
def info_clockchain():
    response = {
        'chain': clockchain.chain,
        'length': len(clockchain.chain),
    }
    return jsonify(response), 200


@app.route('/info/addr', methods=['GET'])
def info():
    return clockchain.addr, 200


@app.route('/info/peers', methods=['GET'])
def info_peers():
    return jsonify({'peers': list(messenger.peers.keys())}), 200


@app.route('/info/pingpool', methods=['GET'])
def info_pingpool():
    # Remap cause we can't jsonify dict directly
    return jsonify(remap(clockchain.pingpool)), 200


def send_mutual_add_requests(peers, get_further_peers=False):
    # Preparing a set of further peers to possibly add later on
    peers_of_peers = set()

    # Mutual add peers
    for peer in peers:
        if peer not in messenger.peers:
            content = {"port": port, 'pubkey': clockchain.pubkey}
            signature = sign(standard_encode(content), clockchain.privkey)
            content['signature'] = signature
            try:
                response = requests.post(
                    peer + '/mutual_add',
                    json=content,
                    timeout=c.config['timeout'])
                peer_addr = response.text
                status_code = response.status_code
                logger.info("contacted " +
                            str(peer_addr) + ", received " +
                            str(status_code))
            except Exception as e:
                logger.debug("no response from peer: " + str(sys.exc_info()))
                continue
            if status_code == 201:
                logger.info("Adding peer " + str(peer))
                messenger.register_peer(peer, peer_addr)

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


def join_network_worker():
    # Sleeping random amount to not have seed-clash (cannot do circular adding
    # of peers at the exact same time as seeds)
    sleeptime = random.randrange(3000) / 1000.0
    logger.debug("Sleeping for " + str(sleeptime) + "s before joining network")
    time.sleep(sleeptime)

    # First add seeds, and get the seeds peers
    peers_of_seeds = send_mutual_add_requests(
        c.config['seeds'], get_further_peers=True)

    # Then add the peers of seeds
    # TODO: Have seeds only return max 8 randomly chosen peers?
    send_mutual_add_requests(peers_of_seeds)

    logger.debug("Peers: " + str(messenger.peers))

    # TODO: Synchronizing latest chain with peers (choosing what the majority?)

    logger.debug("Finished joining network")


if __name__ == '__main__':
    # Set current working directory to the directory of this file
    os.chdir(c.dir_path)

    logger = logging.getLogger('clocklog')

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    join_network_thread = threading.Thread(target=join_network_worker)
    ping_thread = threading.Thread(target=ping_worker)
    tick_thread = threading.Thread(target=tick_worker)

    join_network_thread.start()
    ping_thread.start()
    tick_thread.start()

    # Try ports until one succeeds
    while True:
        try:
            app.run(host='127.0.0.1', port=port)
            break
        except OSError:
            port = port + 1
            pass
