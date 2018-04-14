import threading
from argparse import ArgumentParser
from logic.clockchain import ping_worker, tick_worker
from logic.messenger import join_network_worker
from flask import Flask


if __name__ == '__main__':
    # Instantiate node
    app = Flask(__name__)

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    join_network_thread = threading.Thread(target=join_network_worker)
    ping_thread = threading.Thread(target=ping_worker)
    tick_thread = threading.Thread(target=tick_worker)

    join_network_thread.start()
    ping_thread.start()
    tick_thread.start()

    # Try ports until one succeeds
    while True:
        try:
            app.run(host='127.0.0.1', port=port)
            break
        except OSError:
            port = port + 1
            pass
