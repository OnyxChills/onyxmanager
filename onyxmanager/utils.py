import socket
import json
import logging
import ssl
import configparser
import os
import random
import string
import time
from OpenSSL import crypto
from socketserver import TCPServer, StreamRequestHandler, ThreadingMixIn
from platform import platform

OS = 'OS'
GENERAL = 'general'
SYSTEM = 'system'
NETWORK = 'network'


def os_slash():
    return '\\' if prefact_os() else '/'


def prefact_os():
    return True if platform(0, 1).replace('-', ' ').split(' ', 1)[0] == 'Windows' else False


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


def build_config(type, isWindows, file):
    config = configparser.ConfigParser()
    config[type] = {}

    if type == 'Agent':
        config[type]['ProgramDirectory'] = r'C:\onyxmanager' if isWindows else '/etc/onyxmanager'
        config[type]['LogDirectory'] = config[type]['ProgramDirectory'] + r'\logs' if isWindows else '/var/log/onyxmanager'
        config[type]['KeyDirectory'] = config[type]['ProgramDirectory'] + (r'\keys' if isWindows else '/keys')
        config[type]['ModuleDirectory'] = config[type]['ProgramDirectory'] + (r'\modules' if isWindows else '/modules')

        config[type]['Host'] = '127.0.0.1'
        config[type]['Port'] = '27069'

    elif type == 'Master':
        config[type]['ProgramDirectory'] = r'C:\onyxmanager' if isWindows else '/etc/onyxmanager'
        config[type]['LogDirectory'] = config[type]['ProgramDirectory'] + r'\logs' if isWindows else '/var/log/onyxmanager'
        config[type]['KeyDirectory'] = config[type]['ProgramDirectory'] + (r'\keys' if isWindows else '/keys')
        config[type]['RemoteDirectory'] = config[type]['ProgramDirectory'] + (r'\remotes' if isWindows else '/remotes')
        config[type]['ModuleDirectory'] = config[type]['ProgramDirectory'] + (r'\modules' if isWindows else '/modules')
        config[type]['ListenAddress'] = '127.0.0.1'
        config[type]['Port'] = '27069'

    if not os.path.isdir(config[type]['ProgramDirectory']):
        os.mkdir(config[type]['ProgramDirectory'])
    if not os.path.isdir(config[type]['LogDirectory']):
        os.mkdir(config[type]['LogDirectory'])
    if not os.path.isdir(config[type]['KeyDirectory']):
        os.mkdir(config[type]['KeyDirectory'])
    if not os.path.isdir(config[type]['ModuleDirectory']):
        os.mkdir(config[type]['ModuleDirectory'])

    if type == 'Master':
        if not os.path.isdir(config[type]['RemoteDirectory']):
            os.mkdir(config[type]['RemoteDirectory'])

    with open(file, 'w') as configfile:
        config.write(configfile)

twofactor_authkeys = list()

class OnyxTCPHandler(StreamRequestHandler):
    def handle(self):
        self.data = self.request.recv(2048).strip()

        if self.data == b'':
            pass
        else:
            print('{0} wrote: {1}'.format(self.client_address[0], self.data))
            for prefix in PACKET_PREFIX_LIST:
                if self.data.startswith(bytes(prefix, 'utf-8')):
                    authkey = str(self.data[len(prefix):len(prefix) + 8], 'utf-8')
                    self.clean_twofactor_authkeys()

                    if prefix == 'CACHE.FACTS' and authkey in [key[0] for key in twofactor_authkeys]:
                        self.data = self.data[len(prefix) + len(authkey):]
                        j_device = json.loads(str(self.data, 'utf-8'), encoding='utf-8')
                        try:
                            config_parser = configparser.ConfigParser()
                            config_parser.read(('C:\\onyxmanager\\' if prefact_os() else '/etc/onyxmanager/')
                                               + 'onyxmanager_Master.conf')
                            config = config_parser['Master']

                            with open(config['RemoteDirectory'] + os_slash() + j_device[GENERAL]['uuid'] + '_device.facts', 'w') \
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

                    elif prefix == 'REQ.VERIFY':
                        self.data = self.data[prefix.__len__():]
                        agent_uuid = str(self.data, 'utf-8').upper()
                        try:
                            config_parser = configparser.ConfigParser()
                            config_parser.read(('C:\\onyxmanager\\' if prefact_os() else '/etc/onyxmanager/')
                                               + 'onyxmanager_Master.conf')
                            config = config_parser['Master']

                            with open(config['KeyDirectory'] + os_slash() + 'verified_agents.txt') as file:
                                verified = False
                                for verified_agent in file:
                                    if agent_uuid == verified_agent.strip().upper() and not verified:
                                        logging.info('%s: Agent UUID verified.', prefix)
                                        self.request.send(bytes(prefix + PACKET_RESPONSES[True] + self.add_twofactor_authkey(), 'utf-8'))
                                        verified = True

                                if not verified:
                                    logging.error('Connection to %s failed, agent UUID denied.',
                                                  ({'client': self.client_address[0],
                                                  'port': self.client_address[1]}))
                                    self.request.send(bytes(prefix + PACKET_RESPONSES[False], 'utf-8'))

                        except FileNotFoundError:
                            self.request.send(bytes(prefix + PACKET_RESPONSES[False], 'utf-8'))

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


def prefix_bytes(prefix):
    def decorator(func):
        def send(*args, **kwargs):
            new_args = [arg for arg in args]
            for index, arg in enumerate(args):
                if index != 1:
                    pass
                else:
                    new_args[index] = bytes(str(prefix), 'utf-8') + args[1]
            return func(*new_args, **kwargs)
        return send
    return decorator


def check_verification():
    def decorator(func):
        def send(*args, **kwargs):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ver_sock = OnyxSocket(sock=s,
                                  certfile=args[0].certfile,
                                  keyfile=args[0].keyfile)

            config_parser = configparser.ConfigParser()
            config_parser.read(('C:\\onyxmanager\\' if prefact_os() else '/etc/onyxmanager/')
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
                logging.info('Host denied agent request')
                raise ConnectionRefusedError('Agent UUID was denied by the server.')
        return send
    return decorator


class OnyxSocket(ssl.SSLSocket):
    def set_device(self, device):
        self.device = device

    @check_verification()
    @prefix_bytes('CACHE.FACTS')
    def send_device_cache(self, *args, **kwargs):
        self.send(*args, **kwargs)
        return 'CACHE.FACTS'


PACKET_PREFIX_LIST = ['CACHE.FACTS', 'REQ.VERIFY']
PACKET_RESPONSES = {True: 'SUCCEED', False: 'FAILED'}


def create_self_signed_cert(dir, cert, key):
    cert_file = dir + os_slash() + cert
    key_file = dir + os_slash() + key

    if not os.path.exists(key_file) \
            or not os.path.exists(cert_file):

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = 'CA'
        cert.get_subject().ST = 'Ontario'
        cert.get_subject().L = 'Niagara Falls'
        cert.get_subject().O = 'OnyxChills'
        cert.get_subject().OU = 'OnyxChills'
        cert.get_subject().CN = 'Device-Test'
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(5*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        open(cert_file, 'wt').write(
            str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert), 'utf-8'))
        open(key_file, 'wt').write(
            str(crypto.dump_privatekey(crypto.FILETYPE_PEM, k), 'utf-8'))
