import requests
from urllib.parse import urlparse
from flask import jsonify, request, Flask
from utils.pki import pubkey_to_addr, verify
from utils.helpers import remap, resolve, standard_encode, hasher
from utils.common import logger, config, credentials
from utils.validation import validate_tick, validate_ping, validate_schema
from expiringdict import ExpiringDict


class API(object):
    def __init__(self, clockchain, networker):

        self.clockchain = clockchain
        self.networker = networker

        # cache to avoid processing duplicate json forwards
        self.duplicate_cache = ExpiringDict(
            max_len=config['expiring_dict_max_len'],
            max_age_seconds=config['expiring_dict_max_age'])

    def check_duplicate(self, values):
        # Check if dict values has been received in the past x seconds already
        if self.duplicate_cache.get(hasher(values)):
            return True
        else:
            self.duplicate_cache[hasher(values)] = True
            return False

    def handle_ping(self, ping, vote=False):
        if self.check_duplicate(ping):
            return "duplicate request please wait 10s", 400

        if not validate_ping(ping, self.clockchain.ping_pool, vote):
            return "Invalid ping", 400

        if vote:
            self.clockchain.add_to_vote_pool(ping)
        else:
            self.clockchain.add_to_ping_pool(ping)

        # TODO: Why would anyone forward others pings? Only incentivized
        # TODO: to forward own pings (to get highest uptime)
        # TODO: Solved if you remove peers that do not forward your ping

        route = 'vote' if vote else 'ping'

        redistribute = int(request.args.get('redistribute'))
        if redistribute:
            origin = request.args.get('addr')
            self.networker.forward(data_dict=ping,
                                   route=route,
                                   origin=origin,
                                   redistribute=redistribute)

        return "Added " + route, 201

    def create_app(self):
        app = Flask(__name__)

        @app.route('/forward/tick', methods=['POST'])
        def forward_tick():
            if self.networker.stage == "select":
                return "not accepting further ticks", 400

            tick = request.get_json()

            if self.check_duplicate(tick):
                return "duplicate request please wait 10s", 400

            if not validate_tick(tick, self.clockchain.current_height(),
                                 self.clockchain.possible_previous_ticks()):
                return "Invalid tick", 400

            self.clockchain.add_to_tick_pool(tick)

            # TODO: Sanitize this input..
            redistribute = int(request.args.get('redistribute'))
            if redistribute:
                origin = request.args.get('addr')
                self.networker.forward(data_dict=tick,
                                       route='tick',
                                       origin=origin,
                                       redistribute=redistribute)

            return "Added tick", 201

        @app.route('/forward/ping', methods=['POST'])
        def forward_ping():
            return self.handle_ping(request.get_json(), vote=False)

        @app.route('/forward/vote', methods=['POST'])
        def forward_vote():
            return self.handle_ping(request.get_json(), vote=True)

        # TODO: In the future, create a dns seed with something similar to
        # https://github.com/sipa/bitcoin-seeder
        # TODO: See also
        # https://bitcoin.stackexchange.com/questions/3536/
        # how-do-bitcoin-clients-find-each-other/11273
        @app.route('/mutual_add', methods=['POST'])
        def mutual_add():
            values = request.get_json()

            if self.check_duplicate(values):
                return "duplicate request please wait 10s", 400

            # Verify json schema
            if not validate_schema(values, 'mutual_add_schema.json'):
                return "Invalid request", 400

            # Verify that pubkey and signature match
            signature = values.pop("signature")
            if not verify(standard_encode(values), signature, values['pubkey']):
                return "Invalid signature", 400

            # TODO: What if rogue peer send fake port? Possible ddos reflection?
            # TODO: Do schema validation for integer sizes / string lengths..
            remote_port = int(values.get('port'))

            remote_url = resolve(request.remote_addr)
            remote_url = "http://" + remote_url + ":" + str(remote_port)

            remote_cleaned_url = urlparse(remote_url).netloc
            own_cleaned_url = urlparse(request.url_root).netloc

            # TODO: Add sig validation here?
            #  to make sure peer is who they say they are

            # Avoid inf loop by not adding self..
            if remote_cleaned_url != own_cleaned_url:
                addr = requests.get(remote_url + '/info/addr').text

                # Verify that the host's address matches the key pair used
                # to sign the mutual_add request
                if not pubkey_to_addr(values['pubkey']) == addr:
                    logger.info("Received request signed with key != host")
                    return "Signature does not match address of given host", 400

                if not self.networker.register_peer(remote_url, addr):
                    return "Could not register peer", 400
                else:  # Make sure the new joiner gets my pings (if I have any)
                    if credentials.addr in self.clockchain.ping_pool:
                        ping = self.clockchain.ping_pool[credentials.addr]
                        # Forward but do not redistribute
                        requests.post(
                            remote_url + '/forward/ping?addr=' +
                            credentials.addr + "&redistribute=0",
                            json=ping,
                            timeout=config['timeout'])
            return credentials.addr, 201

        @app.route('/info/clockchain', methods=['GET'])
        def info_clockchain():
            response = {
                'chain': self.clockchain.chainlist()
            }
            return jsonify(response), 200

        @app.route('/info/addr', methods=['GET'])
        def info():
            return credentials.addr, 200

        @app.route('/info/peers', methods=['GET'])
        def info_peers():
            return jsonify({'peers': list(self.networker.peers.keys())}), 200

        @app.route('/info/ping_pool', methods=['GET'])
        def info_ping_pool():
            return jsonify(remap(self.clockchain.ping_pool)), 200

        @app.route('/info/vote_counts', methods=['GET'])
        def info_vote_counts():
            return jsonify(remap(self.clockchain.get_vote_counts())), 200

        return app
