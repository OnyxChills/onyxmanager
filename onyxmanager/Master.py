import logging
import json
import os
import atexit
import configparser
import threading
import queue
import time
import random
import string
import ssl
import socket
from socketserver import TCPServer, StreamRequestHandler, ThreadingMixIn
from onyxmanager import utils, Agent


twofactor_authkeys = list()


class MasterTCPServer(ThreadingMixIn, TCPServer):
    def __init__(self, server_address, RequestHandlerClass, certfile, keyfile, bind_and_activate=True):
        TCPServer.__init__(self,
                           server_address,
                           RequestHandlerClass)

        self.socket = ssl.wrap_socket(socket.socket(self.address_family, self.socket_type),
                                      server_side=True,
                                      certfile=certfile,
                                      keyfile=keyfile,
                                      do_handshake_on_connect=False)

        if bind_and_activate:
            self.server_bind()
            self.server_activate()

    def get_request(self):
        (socket, addr) = TCPServer.get_request(self)
        socket.do_handshake()
        return (socket, addr)

    def shutdown(self):
        self.socket.close()
        super(TCPServer, self).shutdown()


class MasterTCPHandler(StreamRequestHandler):
    def handle(self):
        self.data = self.request.recv(2048).strip()

        if self.data == b'':
            pass
        else:
            print('{0} wrote: {1}'.format(self.client_address[0], self.data))
            for prefix in utils.PACKET_PREFIX_LIST:
                if self.data.startswith(bytes(prefix, 'utf-8')):
                    authkey = str(self.data[len(prefix):len(prefix) + 8], 'utf-8')
                    self.clean_twofactor_authkeys()

                    if prefix == 'CACHE.FACTS' and authkey in [key[0] for key in twofactor_authkeys]:
                        self.handle_cache_facts(prefix, authkey)

                    elif prefix == 'REQ.VERIFY':
                        self.handle_req_verify(prefix)

                    elif prefix == 'REQ.ADD.AGENT':
                        self.handle_req_add_agent(prefix)

    def handle_cache_facts(self, prefix, authkey):
        self.data = self.data[len(prefix) + len(authkey):]
        j_device = json.loads(str(self.data, 'utf-8'), encoding='utf-8')
        try:
            config_parser = configparser.ConfigParser()
            config_parser.read(('C:\\onyxmanager\\' if utils.prefact_os() else '/etc/onyxmanager/')
                               + 'onyxmanager_Master.conf')
            config = config_parser['Master']

            with open(config['RemoteDirectory'] + utils.os_slash() + j_device[utils.GENERAL]['uuid'] + '_device.facts', 'w') \
                    as outfile:
                json.dump(j_device, outfile, sort_keys=True, indent=4)

            self.request.send(bytes(prefix + utils.PACKET_RESPONSES[True], 'utf-8'))
            logging.info('%s: Cached device facts for device UUID=%s',
                         prefix,
                         j_device[utils.GENERAL]['uuid'])
        except ConnectionRefusedError:
            logging.error('Connection to %s failed, is client accessible?',
                          ({'client': self.client_address[0],
                            'port': self.client_address[1]}))

    def handle_req_verify(self, prefix):
        self.data = self.data[prefix.__len__():]
        agent_uuid = str(self.data, 'utf-8').upper()
        try:
            config_parser = configparser.ConfigParser()
            config_parser.read(('C:\\onyxmanager\\' if utils.prefact_os() else '/etc/onyxmanager/')
                               + 'onyxmanager_Master.conf')
            config = config_parser['Master']

            with open(config['KeyDirectory'] + utils.os_slash() + 'verified_agents.txt') as file:
                verified = False
                for verified_agent in file:
                    if agent_uuid == verified_agent.strip().upper() and not verified:
                        logging.info('%s: Agent UUID verified.', prefix)
                        self.request.send(
                            bytes(prefix + utils.PACKET_RESPONSES[True] + self.add_twofactor_authkey(), 'utf-8'))
                        verified = True

                if not verified:
                    logging.error('Connection to %s failed, agent UUID denied.',
                                  ({'client': self.client_address[0],
                                    'port': self.client_address[1]}))
                    self.request.send(bytes(prefix + utils.PACKET_RESPONSES[False], 'utf-8'))

        except FileNotFoundError:
            self.request.send(bytes(prefix + utils.PACKET_RESPONSES[False], 'utf-8'))

    def handle_req_add_agent(self, prefix):
        self.data = self.data[prefix.__len__():]

        config_parser = configparser.ConfigParser()
        config_parser.read(('C:\\onyxmanager\\' if utils.prefact_os() else '/etc/onyxmanager/')
                           + 'onyxmanager_Master.conf')
        config = config_parser['Master']

        with open(config['KeyDirectory'] + utils.os_slash() + 'verified_agents.txt') as file:
            for agent_uuid in file:
                print(agent_uuid)

    def add_twofactor_authkey(self):
        key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))
        now = time.time()
        expiry = time.time() + 5.0                  # This is seconds
        twofactor_authkeys.append((key, now, expiry))

        return key

    def clean_twofactor_authkeys(self):
        for index, authkey in enumerate(twofactor_authkeys):
            now = time.time()
            if now > authkey[2]:
                twofactor_authkeys.pop(index)


class DaemonHandler(StreamRequestHandler):
    TCPServer.allow_reuse_address = True

    def handle(self):
            self.data = self.request.recv(2048).strip()

            if self.data == b'':
                pass
            else:
                print('{0} wrote: {1}'.format(self.client_address[0], self.data))
                for prefix in utils.DAEMON_COMMAND_LIST:
                    if prefix == 'ADD.AGENT':
                        self.handle_add_agent(prefix)

    def handle_add_agent(self, prefix):
        self.data = self.data[prefix.__len__():]

        config_parser = configparser.ConfigParser()
        config_parser.read(('C:\\onyxmanager\\' if utils.prefact_os() else '/etc/onyxmanager/')
                            + 'onyxmanager_Master.conf')
        config = config_parser['Master']

        with open(config['KeyDirectory'] + utils.os_slash() + 'verified_agents.txt') as file:
            for agent_uuid in file:
                print(str(self.data, 'utf-8'))
                print(agent_uuid)
                if agent_uuid in str(self.data.strip().upper(), 'utf-8') :
                    self.request.send(bytes(prefix + utils.PACKET_RESPONSES[False] + 'Agent was already verified.', 'utf-8'))
                else:
                    print('Yay.')


class DeamonCommandServer(TCPServer, ThreadingMixIn):
    pass


class Master:
    def __init__(self):
        self.q = queue.Queue()
        self.threads = []
        self.device_name = 'master'
        self.config_file = ('C:\\onyxmanager\\' if utils.prefact_os() else '/etc/onyxmanager/') + 'onyxmanager_' + 'Master' + '.conf'

        if not os.path.isfile(self.config_file):
            utils.build_config('Master', utils.prefact_os(), self.config_file)

        config_parser = configparser.ConfigParser()
        config_parser.read(self.config_file)
        self.config = config_parser['Master']

        self.log_file = utils.os_slash() + 'master.log'
        logging.basicConfig(filename=self.config['LogDirectory'] + self.log_file,
                            level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s: %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S')

        logging.info('')
        logging.info('OnyxManager Master v%s - Started', '0.0.7')
        logging.info('Log directory set to \'%s\'', self.config['LogDirectory'])
        logging.info('Working directory set to \'%s\'', self.config['ProgramDirectory'])

        try:
            loaded_UUID = json.load(
                open(self.config['ProgramDirectory'] + utils.os_slash() + 'master.facts')
            )[utils.GENERAL]['uuid']

        except FileNotFoundError:
            loaded_UUID = ''
        except KeyError:
            loaded_UUID = ''

        self.device = Agent.Device(self.device_name, dev_uuid=loaded_UUID)
        self.cache_facts()


        self.run_in_thread(self.start_server)
        self.run_in_thread(self.start_controller())

        atexit.register(logging.info, 'OnyxManager Master v%s - Stopped', '0.0.6')
        atexit.register(self.server.shutdown())
        atexit.register(self.commander.shutdown())

    def cache_facts(self):
        try:
            self.device.dump_facts_as_json(self.config['ProgramDirectory'] + utils.os_slash() + 'master.facts')
            logging.info('Device facts dumped to \'%s\'',
                         self.config['ProgramDirectory'] + utils.os_slash() + 'master.facts')
        except Exception as e:
            logging.error('Error: %s', e)
            raise e

    def start_server(self):
        if not os.path.isdir(self.config['KeyDirectory']):
            os.mkdir(self.config['KeyDirectory'])
        utils.create_self_signed_cert(self.config['KeyDirectory'], 'onyxmanager_master.crt', 'onyxmanager_master.key')
        self.server = MasterTCPServer(('', int(self.config['Port'])),
                                          MasterTCPHandler,
                                          self.config['KeyDirectory'] + utils.os_slash() + 'onyxmanager_master.crt',
                                          self.config['KeyDirectory'] + utils.os_slash() + 'onyxmanager_master.key')
        self.server.serve_forever()

    def start_controller(self):
        self.commander = DeamonCommandServer(('', 27068), DaemonHandler)
        self.commander.serve_forever()

    def run_in_thread(self, func, *args, **kwargs):
        t = threading.Thread(target=func, args=args, kwargs=kwargs)
        t.daemon = True
        self.threads.append(t)
        t.start()