import logging
import json
import os
import atexit
import socketserver
from onyxmanager import master_control, utils, Agent

class Master():
    def __init__(self):
        self.device_name = 'master'

        if not os.path.isdir(master_control.working_dir):
            os.mkdir(master_control.working_dir)
        if not os.path.isdir(master_control.log_dir):
            os.mkdir(master_control.log_dir)
        if not os.path.isdir(master_control.remote_fact_dir):
            os.mkdir(master_control.remote_fact_dir)

        self.log_file = utils.os_slash() + 'master.log'
        logging.basicConfig(filename=master_control.log_dir + self.log_file,
                            level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s: %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S')

        logging.info('')
        logging.info('OnyxManager Master v%s - Started', '0.0.5')
        logging.info('Log directory set to \'%s\'', master_control.log_dir)
        logging.info('Working directory set to \'%s\'', master_control.working_dir)

        try:
            loaded_UUID = json.load(
                open(master_control.working_dir + utils.os_slash() + 'master.facts')
            )[utils.GENERAL]['uuid']

        except FileNotFoundError:
            loaded_UUID = ''
        except KeyError:
            loaded_UUID = ''

        self.device = Agent.Device(self.device_name, dev_uuid=loaded_UUID)
        self.cache_facts()
        atexit.register(logging.info, 'OnyxManager Master v%s - Stopped', '0.0.5')

        self.server = socketserver.TCPServer(('', master_control.port), utils.OnyxTCPHandler)

    def cache_facts(self):
        try:
            self.device.dump_facts_as_json(str(master_control.working_dir) + utils.os_slash() + 'master.facts')
            logging.info('Device facts dumped to \'%s\'',
                         str(master_control.working_dir) + utils.os_slash() + 'master.facts')
        except Exception as e:
            logging.error('Error: %s', e)
            raise e
