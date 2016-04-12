import socket
import json
import logging
import ssl
import configparser
import os
from socketserver import TCPServer, StreamRequestHandler, ThreadingMixIn
from platform import platform
from onyxmanager import master_control

OS = 'OS'
GENERAL = 'general'
SYSTEM = 'system'
NETWORK = 'network'


def os_slash():
    return '\\' if prefact_os() else '/'


def prefact_os():
    return True if platform(0, 1).replace('-', ' ').split(' ', 1)[0] == 'Windows' else False


def prefix_bytes(prefix):
    def decorator(func):
        def send(*args, **kwargs):
            new_args = [args[0], bytes(str(prefix), 'utf-8') + args[1]]
            return func(*new_args, **kwargs)
        return send
    return decorator


class OnyxTCPServer(ThreadingMixIn, TCPServer):
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


def build_config(type, isWindows):
    config = configparser.ConfigParser()
    config[type] = {}

    if type == 'Agent':
        config[type]['ProgramDirectory'] = r'C:\onyxmanager' if isWindows else '/etc/onyxmanager'
        config[type]['LogDirectory'] = config[type]['ProgramDirectory'] + r'\logs' if isWindows else '/var/log/onyxmanager'
        config[type]['KeyDirectory'] = config[type]['ProgramDirectory'] + (r'\keys' if isWindows else '/keys')
        config[type]['Host'] = '0.0.0.0'
        config[type]['Port'] = '27069'

    elif type == 'Master':
        config[type]['ProgramDirectory'] = r'C:\onyxmanager' if isWindows else '/etc/onyxmanager'
        config[type]['LogDirectory'] = config[type]['ProgramDirectory'] + r'\logs' if isWindows else '/var/log/onyxmanager'
        config[type]['KeyDirectory'] = config[type]['ProgramDirectory'] + (r'\keys' if isWindows else '/keys')
        config[type]['RemoteDirectory'] = config[type]['ProgramDirectory'] + (r'\remotes' if isWindows else '/remotes')
        config[type]['ListenAddress'] = '127.0.0.1'
        config[type]['Port'] = '27069'

    if not os.path.isdir(config[type]['ProgramDirectory']):
        os.mkdir(config[type]['ProgramDirectory'])
    if not os.path.isdir(config[type]['LogDirectory']):
        os.mkdir(config[type]['LogDirectory'])
    if not os.path.isdir(config[type]['KeyDirectory']):
        os.mkdir(config[type]['KeyDirectory'])

    if type == 'Master':
        if not os.path.isdir(config[type]['RemoteDirectory']):
            os.mkdir(config[type]['RemoteDirectory'])

    with open(config[type]['ProgramDirectory'] + os_slash() + 'onyxmanager_' + type + '.conf', 'w') as configfile:
        config.write(configfile)


class OnyxTCPHandler(StreamRequestHandler):
    def handle(self):
        self.data = self.request.recv(2048).strip()
        print('{0} wrote:'.format(self.client_address[0]))

        for prefix in PACKET_PREFIX_LIST:
            if self.data.startswith(bytes(prefix, 'utf-8')):
                if prefix == 'CACHE.FACTS':
                    self.data = self.data[prefix.__len__():]
                    j_device = json.loads(str(self.data, 'utf-8'), encoding='utf-8')
                    try:
                        with open(master_control.remote_fact_dir +
                                  os_slash() +
                                  j_device[GENERAL]['uuid'] +
                                  '_device.facts', 'w') \
                                as outfile:
                            json.dump(j_device, outfile, sort_keys=True, indent=4)

                        self.request.send(bytes(prefix + PACKET_RESPONSES[True], 'utf-8'))
                        logging.info('%s: Cached device facts for device UUID=%s',
                                     prefix,
                                     j_device[GENERAL]['uuid'])
                    except ConnectionRefusedError:
                        logging.error('Connection to %s failed, is client accessible?',
                                      ({'client': self.client_address[0],
                                        'port': self.client_address[1]}))


class OnyxSocket(ssl.SSLSocket):
    @prefix_bytes('CACHE.FACTS')
    def send_device_cache(self, *args, **kwargs):
        super(OnyxSocket, self).send(*args, **kwargs)
        return 'CACHE.FACTS'


PACKET_PREFIX_LIST = ['CACHE.FACTS']
PACKET_RESPONSES = {True: 'SUCCEED', False: 'FAILED'}
