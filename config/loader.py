import json
import os
dir_path = os.path.dirname(os.path.realpath(__file__))
with open(dir_path + '/config.json') as config_file:
    config = json.load(config_file)