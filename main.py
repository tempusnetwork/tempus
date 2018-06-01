from argparse import ArgumentParser
from threads.api import API
from threads.networker import Networker
from threads.timeminer import Timeminer
from werkzeug.serving import run_simple
from datastructures.clockchain import Clockchain


if __name__ == '__main__':
    # The "pure" instances, one clockchain datastructure and one for messaging
    clockchain = Clockchain()
    networker = Networker()

    # Timeminer handles all network validation, and API exposes messaging
    timeminer = Timeminer(clockchain, networker)
    api = API(clockchain, networker)

    # Parse port as command line argument
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')

    args = parser.parse_args()
    port = args.port

    app = api.create_app()

    # TODO: When project is dockerized below is not needed anymore
    # Try ports until one succeeds
    while True:
        try:
            networker.set_port(port)
            # TODO: Do not run_simple in production mode? What happens?
            # Removed app.run for now due to annoying logging output.
            run_simple('127.0.0.1', port, app)
            break  # Leave break here so infinite loop stops!
        except OSError:
            port = port + 1
            pass

    # Do not add anything below here, as app.run blocks rest of execution
