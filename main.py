from argparse import ArgumentParser
from threads.api import API
from threads.networker import Networker
from threads.timeminer import Timeminer
from utils.common import logger
from datastructures.clockchain import Clockchain


# Function using gunicorn to launch in production mode. Use below cmd to run
# G_PORT=5000; gunicorn "main:build_app(g_port=$G_PORT)" -b localhost:$G_PORT
def build_app(g_port):
    logger.debug("Running in production mode")
    # The "pure" instances, one clockchain datastructure and one for messaging
    g_clockchain = Clockchain()
    g_networker = Networker()

    # Timeminer handles all network validation, and API exposes messaging
    Timeminer(g_clockchain, g_networker)
    g_api = API(g_clockchain, g_networker)

    g_app = g_api.create_app()

    g_networker.port = g_port
    g_networker.activate()

    return g_app


if __name__ == '__main__':
    # This is dev mode, since gunicorn won't reach anything inside __main__
    from werkzeug.serving import run_simple

    clockchain = Clockchain()
    networker = Networker()

    timeminer = Timeminer(clockchain, networker)
    api = API(clockchain, networker)

    app = api.create_app()

    # Try ports until one succeeds
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')

    args = parser.parse_args()
    port = args.port

    while True:
        try:
            networker.set_port(port)
            run_simple('127.0.0.1', port, app)
            break  # Leave break here so infinite loop stops!
        except OSError:
            port = port + 1
            pass

    # Do not add anything below here, as run_simple blocks rest of execution
