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
import bcrypt  # pip install bcrypt

try:
    from PfsenseFauxapi.PfsenseFauxapi import PfsenseFauxapi
except:
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    from PfsenseFauxapi.PfsenseFauxapi import PfsenseFauxapi
# pip3 install pfsense-fauxapi

fauxapi_host = '192.168.89.17'
# fauxapi_host = '192.168.89.253'
fauxapi_apikey = os.getenv('FAUXAPI_APIKEY')
fauxapi_apisecret = os.getenv('FAUXAPI_APISECRET')

aliasdict = {
    'avr': ('AVRORA_10_13_148_D', 'AVRORA_10_13_149_D'),
    'brv': ('BRAVO_192_168_13_D'),
    'kop': ('KOPEIKA_10_50_10_D', 'KOPEIKA_10_50_12_D', 'KOPEIKA_10_50_250_D', 'KOPEIKA_10_81_10_D'),
    'lin': ('LINELLA_10_110_0_D'),
    'loc': ('LOCAL_192_168_89_D'),
    'mag': ('MAGNUM_10_70_122_D', 'MAGNUM_10_70_7_D', 'MAGNUM_172_16_10_D', 'MAGNUM_172_16_11_D'),
    'nov': ('NOVUS_172_16_13_D'),
    'slt': ('SLATA_10_1_54_D'),
    'tab': ('TABYSH_ALL_D'),
}

valid_attributes = ['avr', 'brv', 'kop', 'lin', 'loc', 'mag',
                            'nov', 'slt', 'tab']

def usage():
    print()
    print('usage: ' + sys.argv[0] + ' <mail@cr4.eu>' + ' <192.168.24.i/21>')
    print()
    print('  Environment variables containing credentials MUST be set before use!')
    print('    $ export FAUXAPI_APIKEY=PFFAyourkeyvalue')
    print('    $ export FAUXAPI_APISECRET=devtrashdevtrashdevtrashdevtrashdevtrash')
    print()
    print()
    print()
    print()
    sys.exit(1)

def get_aliases(valid_attributes, aliasdict):
    aliases = []
    for attribute in valid_attributes:
        if type(aliasdict.get(attribute)) is tuple:
            for i in aliasdict.get(attribute):
                aliases.append(i)
        else:
            aliases.append(aliasdict.get(attribute))
    return aliases

# mail = 'kkryzhanivska@c4r.eu'
# tunnel_network = '192.168.24.33/21'
#
# aliases = [
#         'AVRORA_10_13_148_D',
#         'AVRORA_10_13_149_D',
#         'BRAVO_192_168_13_D',
#         'KOPEIKA_10_50_10_D',
#         'KOPEIKA_10_50_12_D',
#         'KOPEIKA_10_50_250_D',
#         'KOPEIKA_10_81_10_D',
#         'LINELLA_10_110_0_D',
#         'LOCAL_192_168_89_D',
#         'MAGNUM_10_70_122_D',
#         'MAGNUM_10_70_7_D',
#         'MAGNUM_172_16_10_D',
#         'MAGNUM_172_16_11_D',
#         'NOVUS_172_16_13_D',
#         'SLATA_10_1_54_D',
#         'TABYSH_ALL_D'
#     ]


class ManagementFauxapiException(Exception):
    pass


class ManagementFauxapi():
    fauxapi_host = None
    fauxapi_apikey = None
    fauxapi_apisecret = None

    system_config = None

    FauxapiLib = None

    def __init__(self, fauxapi_host, fauxapi_apikey, fauxapi_apisecret, debug=False):
        self.FauxapiLib = PfsenseFauxapi(fauxapi_host, fauxapi_apikey, fauxapi_apisecret, debug)

    # user functions
    # =========================================================================

    def get_users(self):
        self._reload_system_config()

        response_data = {}
        for user in self.system_config['system']['user']:
            response_data[user['name']] = user
            del (response_data[user['name']]['name'])
        return response_data

    def add_user(self, username):
        self._reload_system_config()

        user_index, user = self._get_entity('system', 'user', 'name', username)
        if user_index is not None:
            raise ManagementFauxapiException('user already exists', username)

        user = {
            'scope': 'user',
            'bcrypt-hash': 'no-password-set',
            'descr': '',
            'name': username,
            'expires': '',
            'dashboardcolumns': '2',
            'authorizedkeys': '',
            'ipsecpsk': '',
            'webguicss': 'pfSense.css',
            'uid': self._get_next_id('uid'),
        }

        patch_system_user = {
            'system': {
                'user': self.system_config['system']['user']
            }
        }
        patch_system_user['system']['user'].append(user)

        response = self.FauxapiLib.config_patch(patch_system_user)
        if response['message'] != 'ok':
            raise ManagementFauxapiException('unable to add user', response['message'])

        self._increment_next_id('uid')

        return user

    def manage_user(self, username, attributes):
        self._reload_system_config()

        valid_attributes = ['password', 'descr', 'expires', 'dashboardcolumns', 'authorizedkeys', 'ipsecpsk',
                            'webguicss', 'disabled', 'priv']

        user_index, user = self._get_entity('system', 'user', 'name', username)
        if user_index is None:
            raise ManagementFauxapiException('user does not exist', username)

        if type(attributes) != dict:
            raise ManagementFauxapiException('attributes is incorrect type')

        for attribute, value in attributes.items():
            if attribute not in valid_attributes:
                raise ManagementFauxapiException('unsupported attribute type', attribute)

            if attribute == 'disabled':
                if value is True:
                    user[attribute] = ''
                else:
                    if attribute in user:
                        del (user[attribute])
            elif attribute == 'password':
                user['bcrypt-hash'] = bcrypt.hashpw(value.encode('utf8'), bcrypt.gensalt()).decode('utf8')
            else:
                if len(value) == 0 and attribute in user:
                    del (user[attribute])
                elif len(value) > 0:
                    user[attribute] = value

        patch_system_user = {
            'system': {
                'user': self.system_config['system']['user']
            }
        }
        patch_system_user['system']['user'][user_index] = user

        response = self.FauxapiLib.config_patch(patch_system_user)
        if response['message'] != 'ok':
            raise ManagementFauxapiException('unable to manage user', response['message'])

        return user

    def remove_user(self, username):
        self._reload_system_config()

        user_index, user = self._get_entity('system', 'user', 'name', username)
        if user_index is None:
            raise ManagementFauxapiException('user does not exist', username)

        patch_system_user = {
            'system': {
                'user': self.system_config['system']['user']
            }
        }
        del (patch_system_user['system']['user'][user_index])

        response = self.FauxapiLib.config_patch(patch_system_user)
        if response['message'] != 'ok':
            raise ManagementFauxapiException('unable to remove user', response['message'])

        return user

    # alias functions
    # =========================================================================
    def get_aliases(self):
        self._reload_system_config()

        response_data = {}
        for alias in self.system_config['aliases']['alias']:
            response_data[alias['name']] = alias
            del (response_data[alias['name']]['name'])
        return response_data

    def add_alias(self, aliasname, ip):
        self._reload_system_config()

        alias_index, alias = self._get_entity('aliases', 'alias', 'name', aliasname)
        if alias_index is not None:
            raise ManagementFauxapiException('alias already exists', aliasname)

        alias = {
            'name': aliasname,
            'type': 'host',
            'descr': '',
            'address': ip,
            'detail': '2',
            'apply': '',
        }

        patch_aliases_alias = {
            'aliases': {
                'alias': self.system_config['aliases']['alias']
            }
        }
        patch_aliases_alias['aliases']['alias'].append(alias)

        response = self.FauxapiLib.config_patch(patch_aliases_alias)
        if response['message'] != 'ok':
            raise ManagementFauxapiException('unable to add alias', response['message'])

        return alias

    def manage_aliases(self, aliasname, attributes):
        self._reload_system_config()

        valid_attributes = ['type', 'ip', 'descr', 'mail']

        alias_index, alias = self._get_entity('aliases', 'alias', 'name', aliasname)
        # if alias_index is not None:
        #     raise UserGroupManagementFauxapiException('alias already exists', aliasname)

        if type(attributes) != dict:
            raise ManagementFauxapiException('attributes is incorrect type')
        for attribute, value in attributes.items():
            if attribute not in valid_attributes:
                raise ManagementFauxapiException('unsupported attribute type', attribute)

            if attribute == 'ip':
                alias['address'] = alias['address'] + ' ' + value
            elif attribute == 'mail':
                alias['detail'] = alias['detail'] + '||' + value

        patch_aliases_alias = {
            'aliases': {
                'alias': self.system_config['aliases']['alias']
            }
        }
        patch_aliases_alias['aliases']['alias'][alias_index] = alias

        response = self.FauxapiLib.config_patch(patch_aliases_alias)
        if response['message'] != 'ok':
            raise ManagementFauxapiException('unable to add alias', response['message'])
        
        return alias

    # openvpn client specific overrides functions
    # =========================================================================

    def get_openvpn_csc(self):
        self._reload_system_config()

        response_data = {}
        for openvpn_csc in self.system_config['openvpn']['openvpn-csc']:
            response_data[openvpn_csc['common_name']] = openvpn_csc
            del (response_data[openvpn_csc['common_name']]['common_name'])
        return response_data

    def add_openvpn_csc(self, common_name, tunnel_network):
        self._reload_system_config()

        csc_index, openvpn_csc = self._get_entity('openvpn', 'openvpn-csc', 'common_name', common_name)
        if csc_index is not None:
            raise ManagementFauxapiException('openvpn client specific overrides already exists', common_name)

        openvpn_csc = {
            "common_name": common_name,
            "server_list": '1',
            "custom_options": '',
            "block": "",
            "description": common_name,
            "tunnel_network": tunnel_network,
            "tunnel_networkv6": '',
            "local_network": '',
            "local_networkv6": '',
            "remote_network": '',
            "remote_networkv6": '',
            "gwredir": 'yes',
            "push_reset": '',
            "remove_route": '',
            "netbios_enable": '',
            "netbios_ntype": '0',
            "netbios_scope": '',
        }

        patch_csc = {
            'openvpn': {
                'openvpn-csc': self.system_config['openvpn']['openvpn-csc']
            }
        }
        patch_csc['openvpn']['openvpn-csc'].append(openvpn_csc)

        response = self.FauxapiLib.config_patch(patch_csc)
        if response['message'] != 'ok':
            raise ManagementFauxapiException('unable to add openvpn_csc', response['message'])

        return openvpn_csc

    # group functions
    # =========================================================================

    def get_groups(self):
        self._reload_system_config()

        response_data = {}
        for group in self.system_config['system']['group']:
            response_data[group['name']] = group
            del (response_data[group['name']]['name'])
        return response_data

    def add_group(self, groupname):
        self._reload_system_config()

        group_index, group = self._get_entity('system', 'group', 'name', groupname)
        if group_index is not None:
            raise ManagementFauxapiException('group already exists', groupname)

        group = {
            'scope': 'local',
            'description': '',
            'name': groupname,
            'gid': self._get_next_id('gid'),
        }

        patch_system_group = {
            'system': {
                'group': self.system_config['system']['group']
            }
        }
        patch_system_group['system']['group'].append(group)

        response = self.FauxapiLib.config_patch(patch_system_group)
        if response['message'] != 'ok':
            raise ManagementFauxapiException('unable to add group', response['message'])

        self._increment_next_id('gid')

        return group

    def manage_group(self, groupname, attributes):
        self._reload_system_config()

        valid_attributes = ['description', 'member', 'priv']

        group_index, group = self._get_entity('system', 'group', 'name', groupname)
        if group_index is None:
            raise ManagementFauxapiException('group does not exist', groupname)

        if type(attributes) != dict:
            raise ManagementFauxapiException('attributes is incorrect type')

        for attribute, value in attributes.items():
            if attribute not in valid_attributes:
                raise ManagementFauxapiException('unsupported attribute type', attribute)

            if attribute == 'member':
                if type(value) != list:
                    raise ManagementFauxapiException('member attribute is incorrect type')
            elif attribute == 'priv':
                if type(value) != list:
                    raise ManagementFauxapiException('priv attribute is incorrect type')

            if len(value) == 0 and attribute in group:
                del (group[attribute])
            elif len(value) > 0:
                group[attribute] = value

        patch_system_group = {
            'system': {
                'group': self.system_config['system']['group']
            }
        }
        patch_system_group['system']['group'][group_index] = group

        response = self.FauxapiLib.config_patch(patch_system_group)
        if response['message'] != 'ok':
            raise ManagementFauxapiException('unable to manage group', response['message'])

        return group

    def remove_group(self, groupname):
        self._reload_system_config()

        group_index, group = self._get_entity('system', 'group', 'name', groupname)
        if group_index is None:
            raise ManagementFauxapiException('group does not exist', groupname)

        patch_system_group = {
            'system': {
                'group': self.system_config['system']['group']
            }
        }
        del (patch_system_group['system']['group'][group_index])

        response = self.FauxapiLib.config_patch(patch_system_group)
        if response['message'] != 'ok':
            raise ManagementFauxapiException('unable to remove group', response['message'])

        return group

    # internal helper functions
    # =========================================================================

    def _get_entity(self, entity_root, entity_type, entity_key, entity_value):

        entity = None
        entity_index = 0
        for entity_data in self.system_config[entity_root][entity_type]:
            if entity_data[entity_key] == entity_value:
                entity = entity_data
                break
            entity_index += 1

        if entity is None:
            return None, None

        return entity_index, entity

    def _get_next_id(self, id_type):
        id_name = 'next{}'.format(id_type)
        return self.system_config['system'][id_name]

    def _increment_next_id(self, id_type):
        id_name = 'next{}'.format(id_type)
        next_id = int(self._get_next_id(id_type)) + 1
        patch_system_nextid = {
            'system': {
                id_name: str(next_id)
            }
        }
        response = self.FauxapiLib.config_patch(patch_system_nextid)
        if response['message'] != 'ok':
            raise ManagementFauxapiException('unable to increment the nextid', id_type)
        return next_id

    def _reload_system_config(self):
        self.system_config = self.FauxapiLib.config_get()


if __name__ == '__main__':
    # check args and env exist
    if (len(sys.argv) < 3) or not os.getenv('FAUXAPI_APIKEY') or not os.getenv('FAUXAPI_APISECRET'):
        usage()
    elif len(sys.argv) == 3:
        mail = sys.argv[1]
        tunnel_network = sys.argv[2]
        MF = ManagementFauxapi(fauxapi_host, fauxapi_apikey, fauxapi_apisecret)
        openvpn_csc = MF.add_openvpn_csc(mail, tunnel_network)
        exit(0)
    else:
        mail, tunnel_network, *attributes = sys.argv[1:]

    if attributes[0] == '-':
        aliaseslist = get_aliases(valid_attributes, aliasdict)
    else:
        for attribute in attributes:
            if attribute not in valid_attributes:
                usage()
            else:
                valid_attributes.remove(attribute)
        aliaseslist = get_aliases(valid_attributes, aliasdict)


    MF = ManagementFauxapi(fauxapi_host, fauxapi_apikey, fauxapi_apisecret)
    openvpn_csc = MF.add_openvpn_csc(mail, tunnel_network)

    attributes = {
        'ip': tunnel_network[:-3],
        'mail': mail
    }
    for aliasname in aliaseslist:
        user = MF.manage_aliases(aliasname, attributes)

    exit(0)
    # openvpn_csc = MF.get_openvpn_csc()
    # print(openvpn_csc)
    # =========================================================================

    # manage_user attributes
    # attributes = {
    #     'disabled': False,
    #     'descr': 'some new name22222',
    #     # 'password': 'awesomepassword',
    #     # 'expires': '12/25/2025',
    #     # 'authorizedkeys': 'insert-ssh-key-material-here',
    #     # 'priv': ['page-all'],
    # }
    # user = UGMF.manage_user('someuser', attributes)
    # print(json.dumps(user))

    # =========================================================================

    # # add_group
    # group = UGMF.add_group('somegroup')
    # print(json.dumps(group))
    #
    # # manage_group attributes
    # attributes = {
    #     'description': 'some new group name',
    #     'member': [user['uid']],
    #     'priv': ['page-all'],
    # }
    # group = UGMF.manage_group('somegroup', attributes)
    # print(json.dumps(group))

    # =========================================================================

    # # remove_group
    # group = UGMF.remove_group('somegroup')
    # print(json.dumps(group))
    #
    # # remove_user
    # user = UGMF.remove_user('someuser')
    # print(json.dumps(user))
