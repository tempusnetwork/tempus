import logging
import json
import os.path
from utils.pki import get_kp, pubkey_to_addr
from logging.handlers import TimedRotatingFileHandler

# Load config path
this_file_path = os.path.dirname(os.path.realpath(__file__))

# Load parent folder path
dir_path = os.path.abspath(os.path.join(this_file_path, os.pardir))

# Load config file
with open(dir_path + '/config.json') as config_file:
    config = json.load(config_file)

if config['api_backend'] == "flask":
    # Remove annoying misformatted flask output, gets replaced by own logging
    flasklogger = logging.getLogger('werkzeug')
    # Keep serious errors
    flasklogger.setLevel(logging.ERROR)


# Set up logging
logger = logging.getLogger('clocklog')

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

logger.addHandler(handler)

logger.setLevel(logging.DEBUG)

# TODO: Put console level at INFO so you dont see all debug messages
# Print logging to console as well
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(console_formatter)
logger.addHandler(console)

# Create empty credentials object that's importable
# Done with a lambda function so that credentials.* can be assigned
# TODO: Do this safer so a computers memory cant simply be scanned for privkey
credentials = lambda: None

# Use reward address as identifier for this node
if config['generate_rand_addr']:
    credentials.pubkey, credentials.privkey = get_kp()
    logger.debug("Using random addr+privkey: " + credentials.privkey)
else:
    # Assumes priv.json exists containing fixed private key
    # This file is in .gitignore so you don't publish your privkey..
    with open(dir_path + '/utils/priv.json') as privkey_file:
        credentials.privkey = json.load(privkey_file)
    credentials.pubkey, _ = get_kp(privkey=credentials.privkey['priv'])

credentials.addr = pubkey_to_addr(credentials.pubkey)
