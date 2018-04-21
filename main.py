import json
from utils.pki import get_kp
from api.api import create_api
from argparse import ArgumentParser
from logic.messenger import Messenger
from logic.clockchain import Clockchain
from logic.timeminer import Timeminer
from utils.helpers import config, logger, dir_path
from queue import Queue

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

    clockchain = Clockchain(privkey)
    # TODO: Implement message queue for async communications..

    message_queue = Queue()

    messenger = Messenger(message_queue, clockchain)

    # TODO: Block until messenger is "ready", do this with threading...
    messenger.join()

    timeminer = Timeminer(message_queue, clockchain)

    api = create_api(message_queue, clockchain)

    # TODO: When project is dockerized below is not needed anymore
    # Try ports until one succeeds
    while True:
        try:
            messenger.set_port(port)
            api.run(host='127.0.0.1', port=port)
            break  # Leave break here so infinite loop stops!
        except OSError:
            port = port + 1
            pass
