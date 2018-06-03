import socket
from threads.sanic_api import API
from threads.networker import Networker
from threads.timeminer import Timeminer
from utils.common import config, logger
from utils.helpers import handle_exception
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
    g_networker.activate(g_port)

    return g_app


if __name__ == '__main__':
    # This is prod mode using Sanic

    clockchain = Clockchain()
    networker = Networker()

    timeminer = Timeminer(clockchain, networker)
    api = API(clockchain, networker)

    app = api.create_app()

    port = config['default_port']

    # Check which port to use by check which ones taken with sockets
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    while True:
        try:
            # This throws exception if we can't bind
            s.bind(("127.0.0.1", port))
            s.close()

            networker.activate(port)
            app.run(host="127.0.0.1", port=port, access_log=False)
            break  # Leave break here so infinite loop stops!
        except socket.error as e:
            port = port+1
            pass
        except Exception as e:
            handle_exception(e)
            break
