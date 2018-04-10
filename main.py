import os
import logging
import coloredlogs
import threading
from argparse import ArgumentParser
from config.loader import config
from logic.clockchain import ping_worker, tick_worker
from flask import Flask
from logging.handlers import TimedRotatingFileHandler

# Instantiate node
app = Flask(__name__)

logging_formatter = logging.Formatter(fmt=
                                      '%(asctime)s %(module)s %(threadName)s'
                                      ' %(levelname)s: %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')
console_formatter = logging.Formatter(fmt=
                                      '%(asctime)s %(module)-20s '
                                      '%(threadName)-20s'
                                      '%(levelname)-8s: '
                                      '%(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')

# Dated files for logging
os.makedirs(os.path.dirname(config['log_file']), exist_ok=True)
handler = TimedRotatingFileHandler(config['log_file'], backupCount=3,
                                   interval=1, when="d")
handler.suffix = "%Y-%m-%d.log"

handler.setFormatter(logging_formatter)
logger = logging.getLogger('clocklog')
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

# Print to console as well
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(console_formatter)
logging.getLogger('clocklog').addHandler(console)

coloredlogs.install(level='DEBUG', logger=logger,
                    fmt='(%(threadName)-10s) (%(funcName)s) %(message)s')


if __name__ == '__main__':
    logger = logging.getLogger('clocklog')

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
