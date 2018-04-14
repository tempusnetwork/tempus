import requests
from urllib.parse import urlparse
from flask import jsonify, request, Flask
from utils.validation import validate_tick, validate_ping, validate_schema
from utils.pki import pubkey_to_addr, verify
from utils.helpers import remap, resolve, standard_encode, config, logger


class API(object):
    app = Flask(__name__)

    # TODO: See if MVC fits this (API = view, LOGIC = model)
    # TODO: In that case, all references to clockchain and messenger must
    # TODO: Be removed. However, as seen below, this is still tightly coupled..
    def __init__(self, port, clockchain, messenger):
        self.clockchain = clockchain
        self.messenger = messenger
        self.port = port

        # Try ports until one succeeds
        while True:
            try:
                API.app.run(host='127.0.0.1', port=self.port)
                break
            except OSError:
                self.port = self.port + 1
                pass

    @app.route('/forward/tick', methods=['POST'])
    def forward_tick(self):
        tick = request.get_json()

        if self.messenger.check_duplicate(tick):
            return "duplicate request please wait 10s", 400

        if not validate_tick(tick):
            return "Invalid tick", 400

        self.clockchain.chain.append(tick)
        self.clockchain.restart_tick()

        # TODO: Sanitize this input..
        redistribute = int(request.args.get('redistribute'))
        if redistribute:
            origin = request.args.get('addr')
            self.messenger.forward(tick, 'tick', origin,
                                   redistribute=redistribute)

        return "Added tick", 201

    @app.route('/forward/ping', methods=['POST'])
    def forward_ping(self):
        ping = request.get_json()
        if self.messenger.check_duplicate(ping):
            return "duplicate request please wait 10s", 400

        if not validate_ping(ping, self.clockchain.pingpool,
                             check_in_pool=True):
            return "Invalid ping", 400

        # Add to pool
        addr = pubkey_to_addr(ping['pubkey'])
        self.clockchain.pingpool[addr] = ping

        # TODO: Why would anyone forward others pings? Only incentivized
        # to forward own pings (to get highest uptime)
        # TODO: Solved if you remove peers that do not forward your ping

        redistribute = int(request.args.get('redistribute'))
        if redistribute:
            origin = request.args.get('addr')
            self.messenger.forward(ping, 'ping', origin,
                                   redistribute=redistribute)

        return "Added ping", 201

    # TODO: In the future, create a dns seed with something similar to
    # https://github.com/sipa/bitcoin-seeder
    # TODO: See also
    # https://bitcoin.stackexchange.com/questions/3536/
    # how-do-bitcoin-clients-find-each-other/11273
    @app.route('/mutual_add', methods=['POST'])
    def mutual_add(self):
        values = request.get_json()

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
                logger.info("Received request signed with key not matching host")
                return "Signature does not match address of provided host", 400

            if not self.messenger.register_peer(remote_url, addr):
                return "Could not register peer", 400
            else:  # Make sure the new joiner gets my pings (if I have any)
                if self.clockchain.addr in self.clockchain.pingpool:
                    ping = self.clockchain.pingpool[self.clockchain.addr]
                    # Forward but do not redistribute
                    requests.post(
                        remote_url + '/forward/ping?addr=' +
                        self.clockchain.addr + "&redistribute=0",
                        json=ping,
                        timeout=config['timeout'])
        return self.clockchain.addr, 201

    @app.route('/info/clockchain', methods=['GET'])
    def info_clockchain(self):
        response = {
            'chain': self.clockchain.chain,
            'length': len(self.clockchain.chain),
        }
        return jsonify(response), 200

    @app.route('/info/addr', methods=['GET'])
    def info(self):
        return self.clockchain.addr, 200

    @app.route('/info/peers', methods=['GET'])
    def info_peers(self):
        return jsonify({'peers': list(self.messenger.peers.keys())}), 200

    @app.route('/info/pingpool', methods=['GET'])
    def info_pingpool(self):
        # Remap cause we can't jsonify dict directly
        return jsonify(remap(self.clockchain.pingpool)), 200
