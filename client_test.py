from onyxmanager import Agent

if __name__ == '__main__':
    agent = Agent.Agent('OnyxPi-1')

    agent.cache_facts_remotely()
