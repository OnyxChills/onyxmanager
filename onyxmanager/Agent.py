import os
import logging
import socket
import json
import platform
import uuid
import re
import subprocess
import atexit
import configparser
import ssl
from onyxmanager import utils


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
        if self.facts[utils.OS]['isWindows']:
            def parse_ipconfig():
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

            def get_ipconfig_info():
                data = parse_ipconfig()
                for adapter in data:
                    if 'ethernet' in adapter or 'wireless' in adapter:
                        adapter_info = data[adapter]
                        try:
                            adapter_info['media_state']
                        except KeyError:
                            yield adapter, adapter_info

            for adapter_name, adapter_info in get_ipconfig_info():
                try:
                    adapter_info['ipv4_address'] = ''.join(re.findall(r'[0-9]{1,3}\.?', adapter_info['ipv4_address']))
                except:
                    try:
                        adapter_info['ipv4_address'] = ''.join(
                            re.findall(r'[0-9]{1,3}\.?', adapter_info['autoconfiguration_ipv4_address']))
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


def check_verification():
    def decorator(func):
        def send(*args, **kwargs):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ver_sock = AgentSocket(sock=s,
                                  certfile=args[0].certfile,
                                  keyfile=args[0].keyfile)

            config_parser = configparser.ConfigParser()
            config_parser.read(('C:\\onyxmanager\\' if utils.prefact_os() else '/etc/onyxmanager/')
                               + 'onyxmanager_Agent.conf')
            config = config_parser['Agent']

            ver_sock.connect((config['Host'], int(config['Port'])))
            ver_sock.send(bytes('REQ.VERIFY' + args[0].device.facts['general']['uuid'], 'utf-8'))
            received = str(ver_sock.recv(1024), 'utf-8')['REQ.VERIFY'.__len__():]

            if received.startswith('SUCCEED'):
                logging.info('Host verified agent request.')
                data = args[-1:][0]
                new_args = args[:-1] + (bytes(received[7:], 'utf-8') + data,)

                return func(*new_args, **kwargs)
            else:
                logging.info('Host denied agent verification.')
                raise ConnectionRefusedError('Agent UUID was denied by the server.')
        return send
    return decorator


class AgentSocket(ssl.SSLSocket):
    def set_device(self, device):
        self.device = device

    @check_verification()
    @utils.prefix_bytes('CACHE.FACTS')
    def send_device_cache(self, *args, **kwargs):
        self.send(*args, **kwargs)
        return 'CACHE.FACTS'


class Agent:
    def __init__(self, device_name=''):
        self.modules = {}
        self.config_file = ('C:\\onyxmanager\\' if utils.prefact_os() else '/etc/onyxmanager/') + 'onyxmanager_' + 'Agent' + '.conf'

        if not os.path.isfile(self.config_file):
            utils.build_config('Agent', utils.prefact_os(), self.config_file)

        config_parser = configparser.ConfigParser()
        config_parser.read(self.config_file)
        self.config = config_parser['Agent']

        self.log_file = utils.os_slash() + 'agent.log'
        logging.basicConfig(filename=self.config['LogDirectory'] + self.log_file,
                            level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s: %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S')

        logging.info('')
        logging.info('OnyxManager Agent v%s - Started', '0.0.6')
        logging.info('Log directory set to \'%s\'', self.config['LogDirectory'])
        logging.info('Working directory set to \'%s\'', self.config['ProgramDirectory'])

        try:
            loaded_UUID = json.load(
                open(self.config['ProgramDirectory'] + utils.os_slash() + 'agent.facts')
            )['general']['uuid']

        except FileNotFoundError or IOError:
            loaded_UUID = ''
        except KeyError:
            loaded_UUID = ''

        self.device = Device(device_name, dev_uuid=loaded_UUID)

        if not os.path.isdir(self.config['KeyDirectory']):
            os.mkdir(self.config['KeyDirectory'])

        utils.create_self_signed_cert(self.config['KeyDirectory'], 'onyxmanager_agent.crt', 'onyxmanager_agent.key')

        if not os.path.isfile(self.config['ProgramDirectory'] + utils.os_slash() + 'agent.facts'):
            self.cache_facts_locally()

        self.register_modules()
        atexit.register(logging.info, 'OnyxManager Agent v%s - Stopped', '0.0.7')

    def register_modules(self):
        if not os.path.isdir(self.config['ProgramDirectory']):
            os.mkdir(self.config['ProgramDirectory'])
        for file in os.listdir(self.config['ProgramDirectory']):
            if file.endswith('.py'):
                try:
                    self.modules[file[:-3]] = Module(file[:-3],
                                                     self.config['ProgramDirectory']  + utils.os_slash() + file,
                                                     self.device)

                    logging.info('Module \'%s\' added - path=\'%s\'', file[:-3], file)
                except FileNotFoundError:
                    logging.error('Module \'%s\' failed to load, missing file! - path=\'%s\'', file[:-3], file)
                    raise

    def cache_facts_locally(self):
        try:
            self.device.dump_facts_as_json(self.config['ProgramDirectory'] + utils.os_slash() + 'agent.facts')
            logging.info('Device facts dumped to \'%s\'',
                         self.config['ProgramDirectory'] + utils.os_slash() + 'agent.facts')
        except Exception as e:
            logging.error('Error: %s', e)
            raise e

    def cache_facts_remotely(self):
        data = json.dumps(self.device.facts, indent=4)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = AgentSocket(sock=s,
                                certfile=self.config['KeyDirectory'] + utils.os_slash() + 'onyxmanager_agent.crt',
                                keyfile=self.config['KeyDirectory'] + utils.os_slash() + 'onyxmanager_agent.key')

        try:
            sock.connect((self.config['Host'], int(self.config['Port'])))
            sock.set_device(self.device)
            prefix = sock.send_device_cache(bytes(str(data), 'utf-8'))
            received = str(sock.recv(1024), 'utf-8')[prefix.__len__():]


            if received == 'SUCCEED':
                print('Received: {}'.format(received))
                logging.info('Device facts dumped to \'%s\'',
                             self.config['Host'])
            else:
                print('Received: {}'.format('FAILED'))
                logging.info('Device facts could not be dumped to \'%s\'',
                             self.config['Host'])

        except ConnectionRefusedError as reason:
            logging.error('Connection to %s failed, %s', ({'host': self.config['Host'], 'port': int(self.config['Port'])}), reason)


        finally:
            sock.close()
