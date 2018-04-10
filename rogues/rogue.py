from utils.pki import get_kp, sign
import requests
import json


def standard_encode(dictionary):
    return bytes(json.dumps(dictionary, sort_keys=True, separators=(',', ':')), 'utf-8')


with open('config.json') as config_file:
    config = json.load(config_file)

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