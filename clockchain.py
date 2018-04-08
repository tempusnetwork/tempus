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
from urllib.parse import urlparse
import jsonref
import coloredlogs
import pytz
import requests
import ecdsa
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


def hash(dictionary):
    return hashlib.sha256(standard_encode(dictionary)).hexdigest()


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
            # This file is in .gitignore so you don't publish your privkey..
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

    def check_duplicate(self, values):
        # Check if dict values has been received in the past x seconds
        # already..
        if self.duplicate_cache.get(hash(values)):
            return True
        else:
            self.duplicate_cache[hash(values)] = True
            return False

    def current_tick_ref(self):
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

    def restart_tick(self):
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
            logger.debug("Invalid hash for item: "
                         + str(item_copy) + " "
                         + hash(item_copy))
            return False

        # Validate signature
        try:
            encoded_message = standard_encode(item_copy)
            if not verify(encoded_message, signature, item_copy['pubkey']):
                return False
        except ecdsa.BadSignatureError:
            # TODO : When new joiner joins, make sure peers relay latest hash
            print("Bad signature!" + str(item_copy) + " " + str(signature))
            return False

        return True

    def validate_tick(self, tick):
        if not validate_schema(tick, 'tick_schema.json'):
            logger.debug("Failed schema validation")
            return False

        # Check hash and sig keeping in mind signature might be popped off
        if not self.validate_sig_hash(tick):
            logger.debug("Failed signature and hash checking")
            return False

        # Check all pings in list
        for ping in tick['list']:
            valid_ping = self.validate_ping(ping, check_in_pool=False)
            if not valid_ping:
                logger.debug("tick invalid due to containing invalid ping")
                return False

        # TODO: Check timestampdiff larger than X min
        # TODO: Check 90% of prev signatures included

        return True

    def validate_ping(self, ping, check_in_pool=True):
        if not validate_schema(ping, 'ping_schema.json'):
            return False

        # Check addr already not in dict
        if check_in_pool:
            if pubkey_to_addr(ping['pubkey']) in self.pingpool:
                return False

        # Check hash and sig, keeping in mind signature might be popped off
        if not self.validate_sig_hash(ping):
            return False

        # TODO: Sanity check timestamp?
        # TODO: Check if ping references diff hash

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
                logger.debug("no response from peer: " + str(sys.exc_info()))
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
    # TODO: Have seeds only return max 8 randomly chosen peers?
    send_mutual_add_requests(peers_of_seeds)

    logger.debug("Peers: " + str(clockchain.peers))

    # TODO: Synchronizing latest chain with peers (choosing what the majority?)

    logger.debug("Finished joining network")


def ping_worker():
    while True:
        time.sleep(20)
        if not clockchain.added_ping:
            logger.debug("Havent pinged network this round! Starting to mine..")
            ping = {'pubkey': clockchain.pubkey,
                    'timestamp': utcnow(),
                    'reference': clockchain.current_tick_ref()}

            # Always do mining and put nonce after ping construction
            # but before inserting signature
            _, nonce = mine(ping)
            ping['nonce'] = nonce

            signature = sign(standard_encode(ping), clockchain.privkey)
            ping['signature'] = signature

            # Validate own ping
            if not clockchain.validate_ping(ping, check_in_pool=True):
                logger.debug("Failed own ping validation")
                continue  # Skip to next iteration of while loop

            # Add to pool
            addr = pubkey_to_addr(ping['pubkey'])
            clockchain.pingpool[addr] = ping
            clockchain.added_ping = True

            # Forward to peers (this has to be at very end after all validation)
            clockchain.forward(ping, 'ping', clockchain.addr)
            logger.debug("Forwarded own ping: " + str(ping))


# TODO: Consensus mechanism
def tick_worker():
    while True:
        if clockchain.added_ping:
            pass


# Instantiate node
app = Flask(__name__)

logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG', logger=logger,
                    fmt='(%(threadName)-10s) (%(funcName)s) %(message)s')


# Instantiate the clockchain
clockchain = Clockchain()


@app.route('/forward/tick', methods=['POST'])
def forward_tick():
    tick = request.get_json()

    if clockchain.check_duplicate(tick):
        return "duplicate request please wait 10s", 400

    if not clockchain.validate_tick(tick):
        return "Invalid tick", 400

    clockchain.chain.append(tick)
    clockchain.restart_tick()

    # TODO: Sanitize this input..
    redistribute = int(request.args.get('redistribute'))
    if redistribute:
        origin = request.args.get('addr')
        clockchain.forward(tick, 'tick', origin, redistribute=redistribute)

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
