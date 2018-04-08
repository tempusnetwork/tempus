import copy
import hashlib
import json
import logging
import os
import random
import socket
import sys
import threading
import time
import traceback
from datetime import datetime
from statistics import median
from urllib.parse import urlparse
import jsonref
import coloredlogs
import pytz
import requests
from ecdsa import BadSignatureError
from expiringdict import ExpiringDict
from flask import Flask, jsonify, request
from jsonschema import validate

from pki import get_kp, pubkey_to_addr, sign, verify


def utcnow():
    return int(datetime.now(tz=pytz.utc).timestamp())


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
    return bytes(
        json.dumps(dictionary, sort_keys=True, separators=(',', ':')),
        'utf-8')


def validate_schema(dictionary, schema_file):
    absolute_path = dir_path + '/schemas/' + schema_file

    base_path = os.path.dirname(absolute_path)
    base_uri = 'file://{}/'.format(base_path)

    with open(absolute_path) as schema_bytes:
        schema = jsonref.loads(schema_bytes.read(), base_uri=base_uri,
                               jsonschema=True)
    try:
        validate(dictionary, schema)
    except Exception as e:
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


def hash_sum(content):
    content_hash = hash(content)
    return sum([int(digit, 16) for digit in content_hash])


def num_pings(tick):
    return len(tick['list'])


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


class Clockchain(object):

    def __init__(self):
        self.chain = []
        self.peers = {}
        self.pingpool = {}
        self.added_ping = False
        self.grace_period = 1 * 20
        self.tick_candidates = []
        self.forked_hashes = {}

        # cache to avoid processing duplicate json forwards
        self.duplicate_cache = ExpiringDict(
            max_len=config['expiring_dict_max_len'],
            max_age_seconds=config['expiring_dict_max_age'])

        # TODO: Figure out how to decide common genesis
        # tick if all start with diff hashes..
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

        # Create genesis tick
        # TODO: Re-adapt this to use signatures
        genesis_addr = "tempigFUe1uuRsAQ7WWNpb5r97pDCJ3wp9"
        self.chain.append(
            {'addr': genesis_addr, 'nonce': 27033568337, 'list': []})

    def tick_continuity(self, tick):
        # TODO validate with schema
        if tick is None:
            return 0
        previous_addresses = set([ping['pubkey']
                                  for ping in self.chain[-1]['list']])
        current_addresses = set([ping['pubkey'] for ping in tick['list']])
        common_addresses = previous_addresses.intersection(current_addresses)
        if len(previous_addresses) > 0:
            return len(common_addresses) / len(previous_addresses)
        else:
            return 1

    def validate_tick_continuity(self, tick):
        # TODO validate with schema
        if tick is None:
            return False
        if len(self.chain) == 1:
            return True
        logger.debug("Tick continuity: " + str(self.tick_continuity(tick)))
        if self.tick_continuity(tick) > 0.5:
            return True
        return False

    def validate_tick(self, tick):
        # TODO validate with schema
        if not self.validate_tick_continuity(tick):
            logger.info("tick failed continuity validation")
            return False
        if not validate_tick_timestamp(tick):
            logger.info("tick failed timestamp validation")
            return False
        return True

    def purge_by(self, func):
        max_val = func(
            max(
                self.tick_candidates,
                key=func
            )
        )
        self.tick_candidates = [
            candidate
            for candidate in self.tick_candidates
            if func(candidate) == max_val
        ]

    def get_and_replace_chain(self, netloc):
        logger.info("Getting altchain...")
        altchain = json.loads(requests.get(
            netloc + '/info/clockchain').text)['chain']
        logger.info("Received altchain: " + json.dumps(altchain))
        self.chain = altchain
        self.forked_hashes = {}

    def tick_forward(self, candidate_tick=None):
        time.sleep(self.grace_period)
        tick_validated = self.validate_tick(candidate_tick)
        if candidate_tick is not None and tick_validated:
            self.tick_candidates.append(candidate_tick)

        logger.info("Comparing " + str(len(self.tick_candidates)) + " ticks")

        if len(self.tick_candidates) > 1:
            self.purge_by(num_pings)

        if len(self.tick_candidates) > 1:
            self.purge_by(self.tick_continuity)

        if len(self.tick_candidates) > 1:
            self.purge_by(median_ts)

        if len(self.tick_candidates) > 1:
            self.purge_by(hash_sum)

        logger.info("Ticks purged, " + str(len(self.tick_candidates)) + " left")

        winning_tick = self.tick_candidates[0]

        if winning_tick['current_tick_ref'] == self.current_chainhash():
            logger.info("Chosen candidate fits chain, appending")
            self.chain.append(winning_tick)
        else:
            logger.info("Chosen candidate belongs to a fork, getting altchain")
            forked_peers = self.forked_hashes[
                winning_tick['current_tick_ref']]
            logger.info("Forked peer: " + str(forked_peers))
            logger.info("Peers: " + str(self.peers))
            altchain_found = False
            for forked_peer in forked_peers:
                for netloc, peer in self.peers.items():
                    if peer == forked_peer:
                        self.get_and_replace_chain(netloc)
                        altchain_found = True
                    if altchain_found:
                        break
                if altchain_found:
                    break
            if not altchain_found:
                logger.info("Could not find altchain, waiting for next round")
                self.chain.append(candidate_tick)

        logger.info("Candidate chosen")

        self.next_tick()

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
        if redistribute < config['max_hops']:
            # TODO: What happens if malicious actor fakes the ?addr= ?? or the
            # amount of hops?
            for peer in self.peers:
                try:  # Add self.addr in query to identify self to peers
                    # If origin addr is not target peer addr
                    if origin != self.peers[peer]:
                        requests.post(
                            peer + '/forward/' + route + '?addr=' + origin +
                            "&redistribute=" + str(redistribute + 1),
                            json=data_dict, timeout=config['timeout'])
                except Exception as e:
                    logger.debug(str(sys.exc_info()))
                    pass

    def unregister_peer(self, url):
        netloc = urlparse(url).netloc
        del self.peers[netloc]

    def next_tick(self):
        self.added_ping = False
        self.pingpool = {}
        self.tick_candidates = []
        self.forked_hashes = {}

    def validate_sig(self, item):
        item_copy = copy.deepcopy(item)
        signature = item_copy.pop('signature', None)
        if signature is None:
            logger.debug("Could not find signature in validate sig..")
            return False

        # Validate signature
        try:
            if not verify(
                    standard_encode(item_copy),
                    signature,
                    item_copy['pubkey']):
                return False
        except BadSignatureError:
            # TODO : When new joiner joins, make sure seeds/new friends relate
            # the latest hash to them..
            logger.info("Bad signature!" + str(item_copy) + " "
                        + str(signature))
            return False

        return True

    def add_hash_to_forks(self, hash, peer_addr):
        if hash not in self.forked_hashes.keys():
            self.forked_hashes[hash] = []
        self.forked_hashes[hash].append(peer_addr)

    def validate_ping(self, ping, check_in_pool=True):
        if not validate_schema(ping, 'ping_schema.json'):
            return False

        # Check addr already not in dict
        if check_in_pool:
            if pubkey_to_addr(ping['pubkey']) in self.pingpool:
                return False

        # Check hash and signature, keeping in mind signature might be popped
        # off
        if not self.validate_sig(ping):
            return False

        if not ping['current_tick_ref'] == self.current_chainhash():
            self.add_hash_to_forks(
                ping['current_tick_ref'], pubkey_to_addr(ping['pubkey']))
            logger.info('Ping detected referencing different hash; tracking')
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
                    peer + '/mutual_add',
                    json=content,
                    timeout=config['timeout'])
                peer_addr = response.text
                status_code = response.status_code
                logger.info("contacted " +
                            str(peer_addr) + ", received " +
                            str(status_code))
            except Exception as e:
                logger.debug(
                    "no response from peer, "
                    "did not add: " + str(sys.exc_info()))
                continue
            if status_code == 201:
                logger.info("Adding peer " + str(peer))
                clockchain.register_peer(peer, peer_addr)

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
        config['seeds'], get_further_peers=True)

    # Then add the peers of seeds
    send_mutual_add_requests(peers_of_seeds)

    logger.debug("Peers: " + str(clockchain.peers))

    # Above could be done a further step, doing a recursion to
    # discover entire network.
    # Doing this would make for exponential amount of requests however, so
    # only doing it for 1 hop atm.

    # TODO: Synchronizing latest chain with peers (choosing what the majority
    # has?)

    logger.debug("Finished joining network")


def ping_worker():
    while True:
        time.sleep(20)
        if len(clockchain.forked_hashes) > 0:
            logger.info("Alternative hashes found on network")
            for hash, peers in clockchain.forked_hashes.items():
                if len(peers) > 10:
                    logger.info("Althash found with >10 pings, sending altping")

                    ping = {
                        'pubkey': clockchain.pubkey,
                        'timestamp': utcnow()
                    }
                    _, nonce = mine(ping)
                    ping['nonce'] = nonce

                    # Add and remove current hash to make signature
                    ping['current_tick_ref'] = hash
                    signature = sign(standard_encode(ping), clockchain.privkey)
                    ping['signature'] = signature

                    # Forward to peers
                    clockchain.forward(ping, 'ping', clockchain.addr)
                    logger.debug("Forwarded alt ping: " +
                                 str(ping))
        if not clockchain.added_ping:
            logger.debug(
                "Haven't pinged yet, starting...")
            ping = {
                'pubkey': clockchain.pubkey,
                'timestamp': utcnow()
            }
            _, nonce = mine(ping)
            ping['nonce'] = nonce

            # Add and remove current hash to make signature
            ping['current_tick_ref'] = clockchain.current_chainhash()
            signature = sign(standard_encode(ping), clockchain.privkey)
            ping['signature'] = signature

            # Validate own ping
            validation_result = clockchain.validate_ping(
                ping, check_in_pool=True)

            if not validation_result:
                logger.debug("Failed own ping validation")
                continue  # Skip to next iteration of while loop

            # Add to pool
            addr = pubkey_to_addr(ping['pubkey'])
            clockchain.pingpool[addr] = ping

            clockchain.added_ping = True

            # Forward to peers
            clockchain.forward(ping, 'ping', clockchain.addr)
            logger.debug("Forwarded own ping: " + str(ping))


def median_ts(tick):
    # TODO validate with schema
    if len(tick['list']) == 0:
        return -1
    timestamps = [ping['timestamp'] for ping in tick['list']]
    return median(timestamps)


def validate_tick_timestamp(tick):
    # TODO validate with schema
    if tick is None:
        return False
    if len(tick['list']) == 0:
        return True
    if utcnow() - median_ts(tick) >= 1 * 30:
        return True
    else:
        return False


# TODO: If ping is inserted which makes everyone find a viable solution,
# everybody floods network with that solution
# TODO: So need to fix that somehow
def tick_worker():
    while True:
        time.sleep(5)
        logger.info("Checking pingpool")
        if len(list(clockchain.pingpool.values())) == 0:
            logger.info("No pings, waiting")
            continue
        logger.info("Pingpool not empty, building tick")
        current_tick = {
            'pubkey': clockchain.pubkey,
            'list': list(clockchain.pingpool.values())
        }
        logger.info("Checking if tick is ready to forward")
        if clockchain.validate_tick(current_tick):
            logger.info("Timestamp and pings validated, building")
            current_tick[
                'current_tick_ref'] = clockchain.current_chainhash()
            current_tick['signature'] = sign(
                standard_encode(current_tick),
                clockchain.privkey
            )

            # Forward to peers
            logger.info("Forwarding my tick")
            clockchain.forward(current_tick, 'tick', clockchain.addr)

            # Add to own chain and restart
            logger.info("Starting tick procedure")
            clockchain.tick_forward(current_tick)
        elif len(clockchain.tick_candidates) > 0:
            logger.info("Received valid tick, starting tick procedure")
            clockchain.tick_forward()
        else:
            logger.info("No valid ticks yet, waiting")


# Instantiate node
app = Flask(__name__)

logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG', logger=logger,
                    fmt='(%(threadName)-10s) (%(funcName)s) %(message)s')


# Instantiate the clockchain
clockchain = Clockchain()


# TODO: Need to add rogue client which tries to attack the network in as
# many ways as possible
# TODO: This is to learn how to make the network more robust and failsafe
@app.route('/forward/tick', methods=['POST'])
def forward_tick():
    tick = request.get_json()

    if clockchain.check_duplicate(tick):
        return "duplicate request please wait 10s", 400

    validation_result = clockchain.validate_tick(tick)

    if not validation_result:
        return "Invalid tick", 400

    # TODO: Sanitize this input..
    redistribute = int(request.args.get('redistribute'))
    origin = request.args.get('addr')
    if redistribute:
        clockchain.forward(tick, 'tick', origin,
                           redistribute=redistribute)

    if not tick['current_tick_ref'] == clockchain.current_chainhash():
        clockchain.add_hash_to_forks(tick['current_tick_ref'], origin)

    if clockchain.validate_tick(tick):
        clockchain.tick_candidates.append(tick)

    return "Added tick", 201


@app.route('/forward/ping', methods=['POST'])
def forward_ping():
    ping = request.get_json()
    if clockchain.check_duplicate(ping):
        return "duplicate request please wait 10s", 400

    if not clockchain.validate_ping(ping, check_in_pool=True):
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
        clockchain.forward(ping, 'ping', origin, redistribute=redistribute)

    return "Added ping", 201


# TODO: Create a dns seed with a clone from
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

    # TODO: What if rogue peer sends fake port? Can do a mirror ddos?
    # TODO: Do schema validation for integer sizes / string lengths..
    remote_port = int(values.get('port'))

    remote_url = resolve(request.remote_addr)
    remote_url = "http://" + remote_url + ":" + str(remote_port)

    remote_cleaned_url = urlparse(remote_url).netloc
    own_cleaned_url = urlparse(request.url_root).netloc

    # TODO: Add signature validation here? to make sure peer is who they say
    # they are..

    # Avoid inf loop by not adding self..
    if remote_cleaned_url != own_cleaned_url:
        addr = requests.get(remote_url + '/info/addr').text

        # Verify that the host's address matches the key pair used to sign the
        # mutual_add request
        if not pubkey_to_addr(values['pubkey']) == addr:
            logger.info("Received request signed with key not matching host")
            return "Signature does not match address of provided host", 400

        if not clockchain.register_peer(remote_url, addr):
            return "Could not register peer", 400
        else:  # Make sure the new joiner gets my pings (if I have any)
            if clockchain.addr in clockchain.pingpool:
                ping = clockchain.pingpool[clockchain.addr]
                # Forward but do not redistribute
                requests.post(
                    remote_url + '/forward/ping?addr=' +
                    clockchain.addr + "&redistribute=0",
                    json=ping,
                    timeout=config['timeout'])

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
