#!/usr/bin/env python3
#
# Copyright 2018 Nicholas de Jong  <contact[at]nicholasdejong.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os, sys, json

try:
    from PfsenseFauxapi.PfsenseFauxapi import PfsenseFauxapi
except:
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    from PfsenseFauxapi.PfsenseFauxapi import PfsenseFauxapi


# config
fauxapi_host = '192.168.89.17'
fauxapi_apikey = os.getenv('FAUXAPI_APIKEY')
fauxapi_apisecret = os.getenv('FAUXAPI_APISECRET')

# parameters used in the call to UpdateAwsAliasesFauxapi.update() function below
ips = [
    '192.168.24.12',    # smotornyy@c4r.eu
    '192.168.24.13',    # ayakymenko@c4r.eu
    '192.168.24.14',    # ifedoriuk@c4r.eu
    '192.168.24.15',    # pleonenko@c4r.eu
    '192.168.24.16',    # vfedotiuk@c4r.eu
    '192.168.24.17',    # dromash@c4r.eu
    '192.168.24.18',    # dkrinetskiy@c4r.eu
    '192.168.24.19',    # oprykhodko@c4r.eu
    '192.168.24.20',    # pkozubenko@c4r.eu
    '192.168.24.21',    # avityagov@c4r.eu
    '192.168.24.22',    # smoskovkin@c4r.eu
    '192.168.24.23',    # dgulia@c4r.eu
    '192.168.24.24',    # dduplenko@c4r.eu
    '192.168.25.2',     # axeman.ofic@gmail.com
    '192.168.25.3',     # evgeniypilot7@gmail.com
    '192.168.25.4',     # iceslams@gmail.com
    '192.168.24.31'     # aonishchenko@c4r.eu
]
mails = [
    'smotornyy@c4r.eu',        # 192.168.24.12
    'ayakymenko@c4r.eu',       # 192.168.24.13
    'ifedoriuk@c4r.eu',        # 192.168.24.14
    'pleonenko@c4r.eu',        # 192.168.24.15
    'vfedotiuk@c4r.eu',        # 192.168.24.16
    'dromash@c4r.eu',          # 192.168.24.17
    'dkrinetskiy@c4r.eu',      # 192.168.24.18
    'oprykhodko@c4r.eu',       # 192.168.24.19
    'pkozubenko@c4r.eu',       # 192.168.24.20
    'avityagov@c4r.eu',        # 192.168.24.21
    'smoskovkin@c4r.eu',       # 192.168.24.22
    'dgulia@c4r.eu',           # 192.168.24.23
    'dduplenko@c4r.eu',        # 192.168.24.24
    'axeman.ofic@gmail.com',    # 192.168.25.2
    'evgeniypilot7@gmail.com',  # 192.168.25.3
    'iceslams@gmail.com',       # 192.168.25.4
    'aonishchenko@c4r.eu'      # 192.168.24.31
]
ipranges = {
    'AVRORA_10_13_148_D': {
        'ipv4': ips,
        'description': '10.13.148.0/24 - avrora network deny list ',
        'detail': mails
    },
    'AVRORA_10_13_149_D': {
        'ipv4': ips,
        'description': '10.13.149.0/24 - avrora network deny list',
        'detail': mails
    },
    'BRAVO_192_168_13_D': {
        'ipv4': ips,
        'description': '192.168.13.0/24 - bravo network deny list',
        'detail': mails
    },
    'KOPEIKA_10_50_10_D': {
        'ipv4': ips,
        'description': '10.50.10.0/24 - kopeika network deny list',
        'detail': mails
    },
    'KOPEIKA_10_50_12_D': {
        'ipv4': ips,
        'description': '10.50.12.0/24 - kopeika network deny lis',
        'detail': mails
    },
    'KOPEIKA_10_50_250_D': {
        'ipv4': ips,
        'description': '10.50.250.0/24 - kopeika network deny list',
        'detail': mails
    },
    'KOPEIKA_10_81_10_D': {
        'ipv4': ips,
        'description': '10.81.10.0/24 - kopeika network deny list',
        'detail': mails
    },
    'LINELLA_10_110_0_D': {
        'ipv4': ips,
        'description': '10.110.0.0/24 - linella network deny list',
        'detail': mails
    },
    'LOCAL_192_168_89_D': {
        'ipv4': ips,
        'description': '192.168.89.0/24 - service network deny list',
        'detail': mails
    },
    'MAGNUM_10_70_122_D': {
        'ipv4': ips,
        'description': '10.70.122.0/24 - magnum network deny list',
        'detail': mails
    },
    'MAGNUM_10_70_7_D': {
        'ipv4': ips,
        'description': '10.70.7.0/24 - magnum network deny list',
        'detail': mails
    },
    'MAGNUM_172_16_10_D': {
        'ipv4': ips,
        'description': '172.16.10.0/24 - magnum network deny list',
        'detail': mails
    },
    'MAGNUM_172_16_11_D': {
        'ipv4': ips,
        'description': '172.16.11.0/24 - magnum network deny list',
        'detail': mails
    },
    'NOVUS_172_16_13_D': {
        'ipv4': ips,
        'description': '172.16.13.0/24 - novus network deny list',
        'detail': mails
    },
    'SLATA_10_1_54_D': {
        'ipv4': ips,
        'description': '10.1.54.0/24 - slata network deny list',
        'detail': mails
    },
    'TABYSH_ALL_D': {
        'ipv4': ips,
        'description': '13.95.209.224, 51.124.147.58, 51.144.159.66, 52.157.153.172, 52.166.143.42, 52.236.180.209, 195.128.226.53, 195.128.226.54, 195.128.227.243 - tabysh hosts deny list',
        'detail': mails
    }
}


class UpdateAliasesFauxapiException(Exception):
    pass


class UpdateAliasesFauxapi():
    fauxapi_host = None
    fauxapi_apikey = None
    fauxapi_apisecret = None
    system_config = None

    FauxapiLib = None

    def __init__(self, fauxapi_host, fauxapi_apikey, fauxapi_apisecret, debug=False):
        self.FauxapiLib = PfsenseFauxapi(fauxapi_host, fauxapi_apikey, fauxapi_apisecret, debug)

    def update(self):

        # Use FauxapiLib to load the remote system config into memory
        self.system_config = self.FauxapiLib.config_get()

        # download ip-ranges.json parse and iterate
        for name, data in ipranges.items():
            self.update_alias_in_config(
                name=name,
                description=data['description'],
                addresses=data['ipv4'],
                detail=data['detail']
            )

        # Use FauxapiLib to save to the remote system the new edited config
        result = self.FauxapiLib.config_set(self.system_config)
        print(json.dumps(result))

    def update_alias_in_config(self, name, description, addresses, detail):

        # candidate alias to apply
        alias_data = {
            'name': name,
            'type': 'host',
            'address': ' '.join(addresses),
            'descr': description,
            'detail': '||'.join(detail)
        }

        if 'aliases' not in self.system_config or type(self.system_config['aliases']) is not dict:
            self.system_config['aliases'] = {}

        if 'alias' not in self.system_config['aliases'] or type(self.system_config['aliases']['alias']) is not list:
            self.system_config['aliases']['alias'] = []

        alias_found = False
        for index, alias in enumerate(self.system_config['aliases']['alias']):
            if alias['name'] == name:
                alias_found = True
                if alias['address'] != alias_data['address']:
                    self.system_config['aliases']['alias'][index] = alias_data

        if alias_found is False:
            self.system_config['aliases']['alias'].append(alias_data)


if __name__ == '__main__':
    UpdateAliasesFauxapi(fauxapi_host, fauxapi_apikey, fauxapi_apisecret).update()
