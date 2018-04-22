from utils.pki import get_kp, sign
from main import config
from utils.helpers import standard_encode
import requests

# Make a mutual_add request pretending to be another host

target = config['seeds'][0]
spoof = config['seeds'][1]
spoof_port = spoof.split(':')[2]

pub, priv = get_kp()

content = {"port": int(spoof_port), 'pubkey': pub}
signature = sign(standard_encode(content), priv)
content['signature'] = signature

response = requests.post(target + '/mutual_add', json=content, timeout=1000)
print(response.text)