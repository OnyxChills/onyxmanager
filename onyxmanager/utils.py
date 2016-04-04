import socket
import socketserver
import json
from platform import platform

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


class OnyxTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.data = self.request.recv(1024).strip()
        print('{0} wrote:'.format(self.client_address[0]))

        for prefix in PACKET_PREFIX_LIST:
            if self.data.startswith(bytes(prefix, 'utf-8')):
                if prefix == 'CACHE.FACTS':
                    self.data = self.data[prefix.__len__():]
                    j_device = json.loads(str(self.data, 'utf-8'), encoding='utf-8')
                    self.request.send(bytes(prefix + PACKET_RESPONSES[True], 'utf-8'))
                    print('{0}: Cached device facts for device UUID={1}'.format(prefix, j_device[GENERAL]['uuid']))


class OnyxSocket(socket.socket):
    @prefix_bytes('CACHE.FACTS')
    def send_device_cache(self, *args, **kwargs):
        super(OnyxSocket, self).send(*args, **kwargs)
        return 'CACHE.FACTS'


PACKET_PREFIX_LIST = ['CACHE.FACTS']
PACKET_RESPONSES = { True: 'SUCCEED', False: 'FAILED'}
