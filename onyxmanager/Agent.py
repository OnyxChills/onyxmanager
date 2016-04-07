import os
import logging
import socket
import json
import platform
import uuid
import re
import subprocess
import atexit
from onyxmanager import utils, agent_control


class Device:
    def __init__(self, name='', dev_uuid=''):
        self.facts = {
            'OS': {},
            'general': {},
            'system': {},
            'network': {}
        }

        self.j_UUID = dev_uuid

        # Build Facts
        self.build_general_facts(name).build_os_facts().build_network_facts()

    def build_general_facts(self, name=''):
        self.facts[utils.GENERAL]['name'] = socket.gethostname() if name == '' else name
        if self.j_UUID == '':
            try:
                self.facts[utils.GENERAL]['uuid']
            except KeyError:
                self.facts[utils.GENERAL]['uuid'] = str(uuid.uuid4())
            else:
                self.facts[utils.GENERAL]['uuid'] = self.facts[utils.GENERAL]['uuid']
        else:
            self.facts[utils.GENERAL]['uuid'] = self.j_UUID
        return self

    def build_os_facts(self):
        self.facts[utils.OS]['platform'] = platform.platform(0, 1).replace('-', ' ').split(' ', 1)[0]
        self.facts[utils.OS]['isWindows'] = self.facts[utils.OS]['platform'] == 'Windows'
        self.facts[utils.OS]['bit'] = re.match(r'(?P<pre>(\S*))(?P<bit>([63][42])|(armv[0-9]))(?P<post>(\S*))',
                                               str(platform.machine())).group('bit')
        return self

    def build_network_facts(self):
        def parse_ipconfig() -> dict:
            ipconfig = subprocess.Popen('ipconfig /all', stdout=subprocess.PIPE)
            ip_info_bytes = ipconfig.stdout.read().split(b'\r\n')
            ip_info_str = [value.decode('utf-8') for value in ip_info_bytes if value != b'']

            titles = {}
            for value in ip_info_str:
                if value[:3] != '   ':
                    title = value.lower().strip(' ').replace(' ', '_')
                    if title.endswith(':'):
                        titles[title[:-1]] = {}
                        current_title = title[:-1]
                    else:
                        titles[title] = {}
                        current_title = title
                else:
                    try:
                        sub = list(key.strip(' ') for key in value.split(':', 1))
                        titles[current_title].update(
                            {sub[0].lower().replace('.', '').strip(' ').replace(' ', '_'): sub[1]}
                        )
                    except:
                        pass

            return titles


        def get_ip_info() -> (dict, dict):
            data = parse_ipconfig()
            for adapter in data:
                if 'ethernet' in adapter or 'wireless' in adapter:
                    adapter_info = data[adapter]
                    try:
                        adapter_info['media_state']
                    except KeyError:
                        yield adapter, adapter_info

        if self.facts[utils.OS]['isWindows']:
            for adapter_name, adapter_info in get_ip_info():
                try:
                    adapter_info['ipv4_address'] = ''.join(re.findall(r'[0-9]{1,3}\.?', adapter_info['ipv4_address']))
                except:
                    pass

                self.facts[utils.NETWORK][adapter_name] = {'ipv4_address': adapter_info['ipv4_address'],
                                                           'default_gateway': adapter_info['default_gateway'],
                                                           'subnet_mask': adapter_info['subnet_mask'],
                                                           'mac_address': adapter_info['physical_address'],
                                                           'dns_servers': adapter_info['dns_servers']}

        return self

    def build_facts(self):
        self.build_general_facts(self.facts[utils.GENERAL]['name']).build_os_facts().build_network_facts()

    def dump_facts_as_json(self, file_name):
        with open(file_name, 'w') as outfile:
            json.dump(self.facts, outfile, sort_keys=True, indent=4)


class Module:
    def __init__(self, name, file_path, device):
        self.name = name
        self.file_path = file_path
        self.device = device


class Agent:
    def __init__(self, device_name=''):
        self.modules = {}
        self.host = agent_control.host
        self.port = agent_control.port

        if not os.path.isdir(agent_control.log_dir):
            os.mkdir(agent_control.log_dir)
        if not os.path.isdir(agent_control.working_dir):
            os.mkdir(agent_control.working_dir)

        self.log_file = utils.os_slash() + 'agent.log'
        logging.basicConfig(filename=str(agent_control.log_dir + self.log_file),
                            level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s: %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S')

        logging.info('')
        logging.info('OnyxManager Agent v%s - Started', '0.0.5')
        logging.info('Log directory set to \'%s\'', agent_control.log_dir)
        logging.info('Working directory set to \'%s\'', agent_control.working_dir)

        try:
            loaded_UUID = json.load(
                open(agent_control.working_dir + utils.os_slash() + 'device.facts')
            )['general']['uuid']

        except FileNotFoundError:
            loaded_UUID = ''
        except KeyError:
            loaded_UUID = ''

        self.device = Device(device_name, dev_uuid=loaded_UUID)
        self.register_modules()
        atexit.register(logging.info, 'OnyxManager Agent v%s - Stopped', '0.0.5')

    def register_modules(self):
        if not os.path.isdir(agent_control.working_dir):
            os.mkdir(agent_control.working_dir)
        for file in os.listdir(agent_control.working_dir):
            if file.endswith('.py'):
                try:
                    self.modules[file[:-3]] = Module(file[:-3],
                                                     agent_control.working_dir  + utils.os_slash() + file,
                                                     self.device)

                    logging.info('Module \'%s\' added - path=\'%s\'', file[:-3], file)
                except FileNotFoundError:
                    logging.error('Module \'%s\' failed to load, missing file! - path=\'%s\'', file[:-3], file)
                    raise

    def cache_facts_locally(self):
        try:
            self.device.dump_facts_as_json(str(agent_control.working_dir) + utils.os_slash() + 'device.facts')
            logging.info('Device facts dumped to \'%s\'',
                         str(agent_control.working_dir) + utils.os_slash() + 'device.facts')
        except Exception as e:
            logging.error('Error: %s', e)
            raise e

    def cache_facts_remotely(self):
        data = json.dumps(self.device.facts, indent=4)
        sock = utils.OnyxSocket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.connect((self.host, self.port))
            prefix = sock.send_device_cache(bytes(str(data), 'utf-8'))
            received = str(sock.recv(1024), 'utf-8')[prefix.__len__():]

            print('Sent:     {}'.format(data))
            print('Received: {}'.format(received))

            logging.info('Device facts dumped to \'%s\'',
                         self.host)

        except ConnectionRefusedError:
            logging.error('Connection to %s failed, is server up?', ({'host': self.host, 'port': self.port}))

        finally:
            sock.close()
