import json
import os.path
from queue import Queue
from api.api import create_api
from argparse import ArgumentParser
from logic.networker import Networker
from logic.timeminer import Timeminer
from logic.clockchain import Clockchain

# Main contains global variables that should be accessible in all modules

# Load config path
config_path = os.path.dirname(os.path.realpath(__file__))

# Load parent folder path
dir_path = os.path.abspath(os.path.join(config_path, os.pardir))

# Load config file
with open(config_path + '/config.json') as config_file:
    config = json.load(config_file)

# Set up global instances, these are not active until .activate() is run
message_queue = Queue()
clockchain = Clockchain()
networker = Networker()
timeminer = Timeminer()

if __name__ == '__main__':
    # Parse port as command line argument
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')

    args = parser.parse_args()
    port = args.port

    # TODO: Implement message queue for async communications..
    # TODO: Block until messenger is "ready", do this with threading...
    networker.join()

    api = create_api()

    # TODO: When project is dockerized below is not needed anymore
    # Try ports until one succeeds
    while True:
        try:
            networker.set_port(port)
            api.run(host='127.0.0.1', port=port)
            break  # Leave break here so infinite loop stops!
        except OSError:
            port = port + 1
            pass
