import socket
import argparse
from onyxmanager import utils


class DaemonSocket(socket.socket):
    @utils.prefix_bytes('ADD.AGENT')
    def send_add_agent(self, data):
        self.send(data)
        return 'ADD.AGENT'
    pass
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='The OnyxManager controller.')
    parser.add_argument('class',
                        choices=['agent', 'master'],
                        metavar='class',
                        type=str,
                        help='Selects the class of controller to manage, either the agent or the master.')
    parser.add_argument('-V', '--verify-agent',
                        metavar='agent-uuid',
                        type=str,
                        help='Verify a requested agents UUID for access to the Master.')
    args = vars(parser.parse_args())
    print(args)

    sock = DaemonSocket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 27068))

    controller = args['class']
    if controller == 'agent':
        print('Agent')

    if controller == 'master':
        print('Master')

        try:
            agent_uuid = args['verify_agent']
            prefix = sock.send_add_agent(bytes(agent_uuid.strip().upper(), 'utf-8'))
            received = str(sock.recv(1024), 'utf-8')[len(prefix):]

            if received.startswith('SUCCEED'):
                received = received[len('SUCCEED'):]
                print('Recieved: {0}'.format(received))
            else:
                received = received[len('FAILED'):]
                print('Recieved: {0}'.format(received))
        except KeyError:
            pass