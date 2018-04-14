from argparse import ArgumentParser
from logic.clockchain import Clockchain
from logic.messenger import Messenger
from utils.pki import get_kp
from api.api import API
from utils.helpers import config, logger, dir_path
import json

if __name__ == '__main__':
    # Instantiate node
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')

    args = parser.parse_args()
    port = args.port

    # Use reward address as identifier for this node
    if config['generate_rand_addr']:
        _, privkey = get_kp()
        logger.debug("Using random addr + privkey: " + privkey)
    else:
        # Assumes priv.json exists containing fixed private key
        # This file is in .gitignore so you don't publish your privkey..
        with open(dir_path + '/utils/priv.json') as privkey_file:
            privkey = json.load(privkey_file)
        _, privkey = get_kp(privkey=privkey['priv'])

    messenger = Messenger(port, privkey)

    # TODO: Decouple clockchain and messenger... but then must move workers out
    # TODO: In that case, clockchain will be more of a datastructure
    # TODO: And workers would be somewhere else
    clockchain = Clockchain(messenger, privkey)

    api = API(port, clockchain, messenger)
