import requests

from sanic import Sanic
from sanic.response import json, text
from utils.pki import pubkey_to_addr, verify
from utils.helpers import remap, resolve, standard_encode, hasher, attempt
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

    async def check_duplicate(self, values):
        # Check if dict values has been received in the past x seconds already
        if self.duplicate_cache.get(hasher(values)):
            return True
        else:
            self.duplicate_cache[hasher(values)] = True
            return False

    async def handle_ping(self, request, vote=False):
        ping = request.json

        route = 'vote' if vote else 'ping'

        if await self.check_duplicate(ping):
            return text("duplicate request please wait 10s", status=400)

        if not validate_ping(ping, self.clockchain.ping_pool, vote):
            return text("Invalid " + route, status=400)

        if vote:
            self.clockchain.add_to_vote_pool(ping)
        else:
            self.clockchain.add_to_ping_pool(ping)

        # TODO: Why would anyone forward others pings? Only incentivized
        # TODO: to forward own pings (to get highest uptime)
        # TODO: Solved if you remove peers that do not forward your ping
        # TODO: For example by adding "shadow-peers" and checking they have it

        redistribute = int(request.args.get('redistribute'))
        if redistribute:
            origin = request.args.get('addr')
            self.networker.forward(data_dict=ping,
                                   route=route,
                                   origin=origin,
                                   redistribute=redistribute)

        return text("Added " + route, status=201)

    def create_app(self):
        app = Sanic()

        # TODO: Only accept ticks/pings from peers?
        @app.route('/forward/tick', methods=['POST'])
        async def forward_tick(request):
            if self.networker.stage == "select":
                return text("not accepting further ticks", status=400)

            tick = request.json

            if await self.check_duplicate(tick):
                return text("duplicate request please wait 10s", status=400)

            if not validate_tick(tick, self.clockchain.latest_selected_tick(),
                                 self.clockchain.possible_previous_ticks()):
                return text("Invalid tick", status=400)

            self.clockchain.add_to_tick_pool(tick)

            # TODO: Sanitize this input..
            redistribute = int(request.args.get('redistribute'))
            if redistribute:
                origin = request.args.get('addr')
                self.networker.forward(data_dict=tick,
                                       route='tick',
                                       origin=origin,
                                       redistribute=redistribute)

            return text("Added tick", status=201)

        @app.route('/forward/ping', methods=['POST'])
        async def forward_ping(request):
            return await self.handle_ping(request, vote=False)

        @app.route('/forward/vote', methods=['POST'])
        async def forward_vote(request):
            return await self.handle_ping(request, vote=True)

        # TODO: In the future, create a dns seed with something similar to
        # https://github.com/sipa/bitcoin-seeder
        # TODO: See also
        # https://bitcoin.stackexchange.com/questions/3536/
        # how-do-bitcoin-clients-find-each-other/11273
        @app.route('/mutual_add', methods=['POST'])
        async def mutual_add(request):
            values = request.json

            if await self.check_duplicate(values):
                return text("duplicate request please wait 10s", status=400)

            # Verify json schema
            if not validate_schema(values, 'mutual_add_schema.json'):
                return text("Invalid request", status=400)

            # Verify that pubkey and signature match
            signature = values.pop("signature")
            if not verify(standard_encode(values), signature, values['pubkey']):
                return text("Invalid signature", status=400)

            # Return a 503: service unavailable here
            # so that they can try adding my friends instead
            if len(self.networker.peers) > config['max_peers']:
                return text("dont need more peers", status=503)

            # TODO: What if rogue peer send fake port? Possible ddos reflection?
            # TODO: Do schema validation for integer sizes / string lengths..
            remote_port = int(values.get('port'))

            remote_url = resolve(request.ip)
            remote_url = "http://" + remote_url + ":" + str(remote_port)

            own_url = "http://" + request.host

            remote_cleaned_url = self.networker.get_full_location(remote_url)
            own_cleaned_url = self.networker.get_full_location(own_url)

            # Avoid inf loop by not adding self..
            if remote_cleaned_url != own_cleaned_url:
                result, success = attempt(requests.get, False,
                                          url=remote_url + '/info/addr',
                                          timeout=config['timeout'])
                if success:
                    addr = result.text
                else:
                    return text("couldn't get addr", status=400)
                # Verify that the host's address matches the key pair used
                # to sign the mutual_add request
                if not pubkey_to_addr(values['pubkey']) == addr:
                    return text("Received request signed with key != host",
                                status=400)

                if not self.networker.register_peer(remote_url, addr):
                    return text("Could not register peer", status=400)
                else:  # Make sure the new joiner gets my pings (if I have any)
                    if credentials.addr in self.clockchain.ping_pool:
                        ping = self.clockchain.ping_pool[credentials.addr]
                        # Forward but do not redistribute
                        _, success = attempt(
                            requests.post, False,
                            url=remote_url + '/forward/ping?addr=' +
                            credentials.addr + "&redistribute=-1",
                            json=ping, timeout=config['timeout'])

                        if not success:
                            return text("couldnt forward my ping", status=400)
            else:
                return text("cannot add self", status=400)

            return text(credentials.addr, status=201)

        @app.route('/info/clockchain', methods=['GET'])
        async def info_clockchain(request):
            response = {
                'chain': self.clockchain.chainlist()
            }
            return json(response, status=200)

        @app.route('/info/addr', methods=['GET'])
        async def info(request):
            return text(credentials.addr, status=200)

        @app.route('/info/peers', methods=['GET'])
        async def info_peers(request):
            return json({'peers': list(self.networker.peers.keys())},
                        status=200)

        @app.route('/info/ping_pool', methods=['GET'])
        async def info_ping_pool(request):
            return json(remap(self.clockchain.ping_pool), status=200)

        @app.route('/info/vote_counts', methods=['GET'])
        async def info_vote_counts(request):
            return json(remap(self.clockchain.get_vote_counts()), status=200)

        # This is done to unify logging visually.
        @app.middleware('response')
        async def logging_for_sanic(request, response):
            logger.debug(request.ip + " " + request.method + " "
                         + request.path + ": [" + str(response.status)
                         + "] " + response.body.decode('utf-8').replace('\\', ''))

        return app
