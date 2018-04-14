import json
from utils.pki import get_kp
from api.api import create_app
from argparse import ArgumentParser
from logic.messenger import Messenger
from logic.clockchain import Clockchain
from utils.helpers import config, logger, dir_path

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

    messenger = Messenger(privkey)

    # TODO: Decouple clockchain and messenger... but then must move workers out
    # TODO: In that case, clockchain will be more of a datastructure
    # TODO: And workers would be somewhere else
    clockchain = Clockchain(messenger, privkey)

    app = create_app(messenger, clockchain)

    # Try ports until one succeeds
    while True:
        try:
            messenger.set_port(port)
            app.run(host='127.0.0.1', port=port)
            break  # !Leave this here so infinite loop stops!
        except OSError:
            port = port + 1
            pass
