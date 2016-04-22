import configparser
import os
import logging
from OpenSSL import crypto
from platform import platform

OS = 'OS'
GENERAL = 'general'
SYSTEM = 'system'
NETWORK = 'network'


def os_slash():
    return '\\' if prefact_os() else '/'


def prefact_os():
    return True if platform(0, 1).replace('-', ' ').split(' ', 1)[0] == 'Windows' else False


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


PACKET_PREFIX_LIST = ['CACHE.FACTS', 'REQ.VERIFY', 'REQ.ADD.AGENT']
PACKET_RESPONSES = {True: 'SUCCEED', False: 'FAILED'}
DAEMON_COMMAND_LIST = ['ADD.AGENT', 'REMOVE.AGENT']


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

        logging.info('Generated SSL certificates as none were present.')
