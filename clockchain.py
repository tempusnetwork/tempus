import hashlib
import json
import random
from urllib.parse import urlparse
import sys
import threading
import traceback
import requests
from flask import Flask, jsonify, request
from jsonschema import validate
import time
from random import sample
from statistics import stdev, mean
from math import log
import coloredlogs
import logging
import socket
import copy
from ecdsa import BadSignatureError
import os
from statistics import median
from datetime import datetime

from pki import get_kp, pubkey_to_addr, sign, verify

from expiringdict import ExpiringDict

# Set current working directory to the directory of this file
dir_path = os.path.dirname(os.path.realpath(__file__))
os.chdir(dir_path)

with open(dir_path + '/config/config.json') as config_file:
    config = json.load(config_file)

difficulty = config['difficulty']


def remap(mapping):
    return [{'key': k, 'value': v} for k, v in mapping.items()]


def resolve(ip):
    return socket.gethostbyaddr(ip)[0]


# Encode dicts (messages loaded from JSON for example) in standard way
def standard_encode(dictionary):
    return bytes(json.dumps(dictionary, sort_keys=True, separators=(',', ':')), 'utf-8')


def validate_schema(dictionary, schema):
    # Check that the required fields are in the dict
    with open(schema) as data_file:
        schema = json.load(data_file)
    try:
        validate(dictionary, schema)
    except BaseException:
        logger.debug("Invalid/missing values: " + str(sys.exc_info()))
        logger.debug(traceback.format_exc())
        return False
    return True


# TODO: Fix stupid rehashing done when wanting a list... the recursion is
# done way too many times!
def hash(content, times=1):
    encoded = standard_encode(content)
    if times > 1:  # Repeated hash for ping calculation
        return hash(hashlib.sha256(encoded).hexdigest(), times - 1)
    elif times == 0:
        return content
    else:
        return hashlib.sha256(encoded).hexdigest()


def similar(a, b):
    total = 0
    for i in range(64):
        total += abs(int(a[i], 16) - int(b[i], 16))

    maximum = 15 * 64
    fraction = total / maximum
    similarity = 1 - fraction

    return similarity


# TODO: Do this in C or other efficient lib..
def mine(content=None):
    nonce = random.randrange(config['max_randint'])
    while True:
        content['nonce'] = nonce
        hashed = hash(content)
        if hashed[-difficulty:] == "0" * difficulty:
            break
        nonce += random.randrange(config['nonce_jump'])
    return hashed, nonce


def evaluate_collection_hashes(collection, permuted):
    if len(permuted) < 2:
        return 0

    permuted = [hash(ping) for ping in permuted]

    sims = []
    for idx, curr_hash in enumerate(permuted):
        similarity = similar(curr_hash, hash(collection, idx))
        sims.append(similarity)

    avg = mean(sims)
    spread = stdev(sims)

    # TODO: Find other solution than using log length of list - this incentivizes spam!!
    # TODO: You put it there temporarily because just avg*spread was higher
    # for smaller lists, which is undesirable
    score = avg * spread * log(len(permuted))
    return score


def smart_permute_list(items_list):
    length = len(items_list)
    indices = [i for i in range(length)]

    # TODO: Permute in clever fashion (box-packing problem?) right now is a
    # random ordering
    ordering = sample(indices, length)
    permuted_list = [items_list[i] for i in ordering]
    return permuted_list, ordering


class Clockchain(object):

    def __init__(self):
        self.chain = []
        self.peers = {}
        self.pingpool = {}
        self.added_ping = False

        # cache to avoid processing duplicate json forwards
        self.duplicate_cache = ExpiringDict(max_len=config['expiring_dict_max_len'],
                                            max_age_seconds=config['expiring_dict_max_age'])

        # TODO: Figure out how to decide common genesis block if all start with diff hashes..
        # Use reward address as identifier for this node
        if config['generate_rand_addr']:
            self.pubkey, self.privkey = get_kp()
            self.addr = pubkey_to_addr(self.pubkey)
            logger.debug("Using random addr + privkey: " + self.privkey)
        else:
            # Assumes priv.json exists containing fixed private key
            with open(dir_path + '/config/priv.json') as privkey_file:
                privkey = json.load(privkey_file)

            self.pubkey, self.privkey = get_kp(privkey=privkey['priv'])

            self.addr = pubkey_to_addr(self.pubkey)

        logger.debug("This node is " + self.addr)

        # Create genesis collect
        # TODO: Re-adapt this to use signatures
        genesis_addr = "tempigFUe1uuRsAQ7WWNpb5r97pDCJ3wp9"
        self.chain.append(
            {'addr': genesis_addr, 'nonce': 27033568337, 'list': []})

    def check_duplicate(self, values):
        # Check if dict values has been received in the past x seconds
        # already..
        if self.duplicate_cache.get(hash(values)):
            return True
        else:
            self.duplicate_cache[hash(values)] = True
            return False

    def current_chainhash(self):
        return hash(self.chain[-1])

    def get_pingpool_hashes_list(self, include_own_ping, ping_dict=None):
        hashes = []
        if ping_dict is None:
            ping_dict = self.pingpool

        # Uses deepcopy otherwise altering the ping_dict itself!
        ping_dict_copy = copy.deepcopy(ping_dict)

        if not include_own_ping:
            ping_dict_copy.pop(clockchain.addr, None)

        for k, v in ping_dict_copy.items():
            v.pop('signature')
            hashes.append(hash(v))

        return hashes

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
        :param route: which route it's addressed at (for ex, forwarding a txn, a peer, etc)
        :param origin: origin of this forward
        :param redistribute: Amount of hops (redistributions through peers) this json message has passed through
        :return: void
        """
        # TODO: Right now max hops is set to 1.... meaning no redistribution.  Good cause we have full netw connectivity
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
                        requests.post(peer + '/forward/' + route + '?addr=' + origin +
                                      "&redistribute=" + str(redistribute + 1), json=data_dict, timeout=config['timeout'])
                except BaseException:
                    logger.debug(str(sys.exc_info()))
                    pass

    def unregister_peer(self, url):
        netloc = urlparse(url).netloc
        del self.peers[netloc]

    def restart_collect(self):
        self.added_ping = False
        self.pingpool = {}

    def validate_sig_hash(self, item):
        item_copy = copy.deepcopy(item)
        signature = item_copy.pop('signature', None)
        if signature is None:
            logger.debug("Could not find signature in validate sighash..")
            return False

        # Check hash
        if hash(item_copy)[-difficulty:] != "0" * difficulty:
            logger.debug("Invalid hash for item: " +
                         item_copy + " " + hash(item_copy))
            return False

        # Adding current collect reference, signature will only match if our own and peers collect references match
        # TODO: Figure out if this messes with consensus mechanism, or enhances
        # it
        item_copy['current_collect_ref'] = self.current_chainhash()

        # Validate signature
        try:
            if not verify(standard_encode(item_copy), signature, item_copy['pubkey']):
                return False
        except BadSignatureError:
            # TODO : When new joiner joins, make sure seeds/new friends relate
            # the latest hash to them..
            print(
                "Mismatch in signature validation, possibly due to chain split / simultaneous solutions found")
            return False

        return True

    def validate_collect(self, collect):
        if not validate_schema(collect, dir_path + '/schemas/collect_schema.json'):
            logger.debug("Failed schema validation")
            return False

        # Check hash and signature, keeping in mind signature might be popped
        # off
        if not self.validate_sig_hash(collect):
            logger.debug("Failed signature and hash checking")
            return False

        # Check all pings in list
        for ping in collect['list']:
            valid_ping = self.validate_ping(ping, check_in_pool=False)
            if not valid_ping:
                logger.debug("Invalid ping for collect")
                return False

        # Check that score is high enough
        score = evaluate_collection_hashes(
            self.current_chainhash(), collect['list'])
        if score <= config['score_limit']:
            logger.debug("Score below score limit:" + str(score))
            return False

        return True

    def validate_ping(self, ping, check_in_pool=True):
        if not validate_schema(ping, dir_path + '/schemas/ping_schema.json'):
            return False

        # Check addr already not in dict
        if check_in_pool:
            if pubkey_to_addr(ping['pubkey']) in self.pingpool:
                return False

        # Check hash and signature, keeping in mind signature might be popped
        # off
        if not self.validate_sig_hash(ping):
            return False

        return True


def send_mutual_add_requests(peers, get_further_peers=False):
    # Preparing a set of further peers to possibly add later on
    peers_of_peers = set()

    # Mutual add peers
    for peer in peers:
        if peer not in clockchain.peers:
            content = {"port": port, 'pubkey': clockchain.pubkey}
            signature = sign(standard_encode(content), clockchain.privkey)
            content['signature'] = signature
            try:
                response = requests.post(
                    peer + '/mutual_add', json=content, timeout=config['timeout'])
                peer_addr = response.text
                status_code = response.status_code
            except BaseException:
                logger.debug(
                    "no response from peer, did not add: " + str(sys.exc_info()))
                continue
            if status_code == 201:
                clockchain.register_peer(peer, peer_addr)

                # Get all peers of current discovered peers and add to set (set is to avoid duplicates)
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
        config['seeds'], get_further_peers=True)

    # Then add the peers of seeds
    send_mutual_add_requests(peers_of_seeds)

    # Above could be done a further step, doing a recursion to discover entire network.
    # Doing this would make for exponential amount of requests however, so
    # only doing it for 1 hop atm.

    # TODO: Synchronizing latest chain with peers (choosing what the majority
    # has?)

    logger.debug("Finished joining network")


def ping_worker():
    while True:
        time.sleep(20)
        if not clockchain.added_ping:
            logger.debug(
                "Havent pinged network for this round! Starting to mine..")
            ping = {'pubkey': clockchain.pubkey}
            _, nonce = mine(ping)
            ping['nonce'] = nonce

            # Add and remove current hash to make signature
            ping['current_collect_ref'] = clockchain.current_chainhash()
            signature = sign(standard_encode(ping), clockchain.privkey)
            ping['signature'] = signature

            ping.pop('current_collect_ref', None)

            # Validate own ping
            validation_result = clockchain.validate_ping(
                ping, check_in_pool=True)

            if not validation_result:
                logger.debug("Failed own ping validation")
                continue  # Skip to next iteration of while loop

            # Add to pool
            addr = pubkey_to_addr(ping['pubkey'])
            clockchain.pingpool[addr] = {
                "nonce": nonce, "signature": signature, "pubkey": clockchain.pubkey}

            clockchain.added_ping = True

            # Forward to peers
            clockchain.forward(ping, 'ping', clockchain.addr)
            logger.debug("Forwarded own ping: " + str(ping))


def median_ts(block):
    timestamps = [
        ping['timestamp'] for ping in block['list']
    ]
    return datetime.fromtimestamp(median(timestamps))


def forge_worker():
    while True:
        if clockchain.added_ping:
            curr_collect_hash = clockchain.current_chainhash()

            ping_list = list(clockchain.pingpool.values())

            if len(ping_list) == 0:
                clockchain.restart_collect()
                logger.error(
                    "Got signalled it was found before me.. putting own hash again.. (via len pinglist)")
                continue

            if curr_collect_hash != clockchain.current_chainhash():  # Restart
                logger.error(
                    "Got signalled it was found before me.. putting own hash again.. (via currblock diff)")
                clockchain.restart_collect()
                continue


# TODO: When two solutions found by 2 verifiers at the same time, the network splits
# TODO: Need to design consensus mechanism - splitting network halves the
# pings??

# TODO: If ping is inserted which makes everyone find a viable solution, everybody floods network with that solution
# TODO: So need to fix that somehow
def collect_worker():
    while True:
        if clockchain.added_ping:
            curr_collect_hash = clockchain.current_chainhash()

            ping_list = list(clockchain.pingpool.values())

            if len(ping_list) == 0:
                clockchain.restart_collect()
                logger.error(
                    "Got signalled it was found before me.. putting own hash again.. (via len pinglist)")
                continue

            # set include_own_ping=False because my ping is included already in
            # the collect
            hashes_list = clockchain.get_pingpool_hashes_list(
                ping_dict=clockchain.pingpool, include_own_ping=False)

            _, ordering = smart_permute_list(hashes_list)

            permuted_ping_list = [ping_list[i] for i in ordering]

            collect = {'pubkey': clockchain.pubkey, 'list': permuted_ping_list}

            _, candidate_nonce = mine(collect)

            if curr_collect_hash != clockchain.current_chainhash():  # Restart
                logger.error(
                    "Got signalled it was found before me.. putting own hash again.. (via currblock diff)")
                clockchain.restart_collect()
                continue

            score = evaluate_collection_hashes(
                curr_collect_hash, permuted_ping_list)

            if score > config['score_limit']:

                collect['nonce'] = candidate_nonce

                # Add and remove current hash to make signature
                collect['current_collect_ref'] = clockchain.current_chainhash()
                collect['signature'] = sign(
                    standard_encode(collect), clockchain.privkey)
                collect.pop('current_collect_ref', None)

                # Validate own collect
                validation_result = clockchain.validate_collect(collect)
                print(collect)
                if not validation_result:
                    logger.debug("Failed own collect validation")
                    continue  # Skip to next iteration of while loop

                logger.debug("Solved collect of size " +
                             str(len(permuted_ping_list)) + ", with contents " + str(collect))

                # Add to own chain and restart ping collecting
                clockchain.chain.append(collect)

                clockchain.restart_collect()

                # Forward to peers
                clockchain.forward(collect, 'collect', clockchain.addr)
                logger.debug("Forwarded own collect: " + str(collect))

            else:
                logger.warning("Only achieved " + str(score) + " score for " + curr_collect_hash + " using "
                               + str(len(permuted_ping_list)) + " pings")


# Instantiate node
app = Flask(__name__)

logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG', logger=logger,
                    fmt='(%(threadName)-10s) %(message)s')


# Instantiate the clockchain
clockchain = Clockchain()


# TODO: Need to add rogue client which tries to attack the network in as many ways as possible
# TODO: This is to learn how to make the network more robust and failsafe
@app.route('/forward/collect', methods=['POST'])
def forward_collect():
    collect = request.get_json()

    if clockchain.check_duplicate(collect):
        return "duplicate request please wait 10s", 400

    validation_result = clockchain.validate_collect(collect)

    if not validation_result:
        return "Invalid collect", 400

    clockchain.chain.append(collect)

    clockchain.restart_collect()

    # TODO: Sanitize this input..
    redistribute = int(request.args.get('redistribute'))
    if redistribute:
        origin = request.args.get('addr')
        clockchain.forward(collect, 'collect', origin,
                           redistribute=redistribute)

    return "Added collect", 201


@app.route('/forward/ping', methods=['POST'])
def forward_ping():
    ping = request.get_json()
    if clockchain.check_duplicate(ping):
        return "duplicate request please wait 10s", 400

    validation_result = clockchain.validate_ping(ping, check_in_pool=True)

    if not validation_result:
        return "Invalid ping", 400

    # Add to pool
    addr = pubkey_to_addr(ping['pubkey'])
    clockchain.pingpool[addr] = ping

    # TODO: Why would anyone forward others pings? Only incentivized to forward own pings (to get highest uptime)
    # TODO: Partially solved by the need to have at least as many pings as
    # previous collect

    redistribute = int(request.args.get('redistribute'))
    if redistribute:
        origin = request.args.get('addr')
        clockchain.forward(ping, 'ping', origin, redistribute=redistribute)

    return "Added ping", 201


# TODO: Create a dns seed with a clone from https://github.com/sipa/bitcoin-seeder
# TODO: See also
# https://bitcoin.stackexchange.com/questions/3536/how-do-bitcoin-clients-find-each-other/11273
@app.route('/mutual_add', methods=['POST'])
def mutual_add():
    values = request.get_json()

    # Verify json schema
    if not validate_schema(values, dir_path + '/schemas/mutual_add_schema.json'):
        return "Invalid request", 400

    # Verify that pubkey and signature match
    signature = values.pop("signature")
    if not verify(standard_encode(values), signature, values['pubkey']):
        return "Invalid signature", 400

    # TODO: What if rogue peer sends fake port? Can do a mirror ddos?
    # TODO: Do schema validation for integer sizes / string lengths..
    remote_port = int(values.get('port'))

    remote_url = resolve(request.remote_addr)
    remote_url = "http://" + remote_url + ":" + str(remote_port)

    remote_cleaned_url = urlparse(remote_url).netloc
    own_cleaned_url = urlparse(request.url_root).netloc

    # TODO: Add signature validation here? to make sure peer is who they say
    # they are..
    if remote_cleaned_url != own_cleaned_url:  # Avoid inf loop by not adding self..
        addr = requests.get(remote_url + '/info/addr').text

        # Verify that the host's address matches the key pair used to sign the
        # mutual_add request
        if not pubkey_to_addr(values['pubkey']) == addr:
            print("Received mutual_add request signed with key not matching host")
            return "Signature does not match address of provided host", 400

        if not clockchain.register_peer(remote_url, addr):
            return "Could not register peer", 400
        else:  # Make sure the new joiner gets my pings (if I have any)
            if clockchain.addr in clockchain.pingpool:
                ping = clockchain.pingpool[clockchain.addr]
                # Forward but do not redistribute
                requests.post(remote_url + '/forward/ping?addr=' + clockchain.addr + "&redistribute=0",
                              json=ping, timeout=config['timeout'])

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
    return jsonify({'peers': list(clockchain.peers.keys())}), 200


# TODO: Remove this fullpeers below, now for bugtesting
@app.route('/info/fullpeers', methods=['GET'])
def info_fullpeers():
    return jsonify(clockchain.peers), 200


@app.route('/info/pingpool', methods=['GET'])
def info_pingpool():
    # Remap cause we can't jsonify dict directly
    return jsonify(remap(clockchain.pingpool)), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    join_network_thread = threading.Thread(target=join_network_worker)
    ping_thread = threading.Thread(target=ping_worker)
    collect_thread = threading.Thread(target=collect_worker)

    join_network_thread.start()
    ping_thread.start()
    collect_thread.start()

    # Try ports until one succeeds
    while True:
        try:
            app.run(host='127.0.0.1', port=port)
            break
        except OSError:
            port = port + 1
            pass
