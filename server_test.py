import os
import sys
from onyxmanager import Master, utils

if __name__ == '__main__':
    if os.geteuid() != 0 and not utils.prefact_os():
        print('Must be run as root.')
        os.execvp('sudo', ['sudo', sys.executable] + sys.argv)

    master = Master.Master()

    master.server.serve_forever()
