import socket
import json
import logging
import ssl
from socketserver import TCPServer, StreamRequestHandler, ThreadingMixIn
from platform import platform
from onyxmanager import master_control

OS = 'OS'
GENERAL = 'general'
SYSTEM = 'system'
NETWORK = 'network'


def os_slash():
    return '\\' if platform(0, 1).replace('-', ' ').split(' ', 1)[0] == 'Windows' else '/'


def prefix_bytes(prefix: str):
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


class OnyxTCPHandler(StreamRequestHandler):
    def handle(self):
        self.data = self.request.recv(1024).strip()
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
