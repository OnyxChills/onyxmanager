import os
import sys
from onyxmanager import Agent, utils

if __name__ == '__main__':
    if not utils.prefact_os():
        if os.geteuid() != 0:
            print('Must be run as root.')
            os.execvp('sudo', ['sudo', sys.executable] + sys.argv)

    agent = Agent.Agent('TestClient')

    agent.cache_facts_remotely()
