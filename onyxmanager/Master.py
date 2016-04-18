import logging
import json
import os
import atexit
import configparser
import threading
import queue
from onyxmanager import utils, Agent


class Master():
    def __init__(self):
        self.q = queue.Queue()
        self.threads = []
        self.device_name = 'master'
        self.config_file = ('C:\\onyxmanager\\' if utils.prefact_os() else '/etc/onyxmanager/') + 'onyxmanager_' + 'Master' + '.conf'

        if not os.path.isfile(self.config_file):
            utils.build_config('Master', utils.prefact_os(), self.config_file)

        config_parser = configparser.ConfigParser()
        config_parser.read(self.config_file)
        self.config = config_parser['Master']

        self.log_file = utils.os_slash() + 'master.log'
        logging.basicConfig(filename=self.config['LogDirectory'] + self.log_file,
                            level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s: %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S')

        logging.info('')
        logging.info('OnyxManager Master v%s - Started', '0.0.5')
        logging.info('Log directory set to \'%s\'', self.config['LogDirectory'])
        logging.info('Working directory set to \'%s\'', self.config['ProgramDirectory'])

        try:
            loaded_UUID = json.load(
                open(self.config['ProgramDirectory'] + utils.os_slash() + 'master.facts')
            )[utils.GENERAL]['uuid']

        except FileNotFoundError:
            loaded_UUID = ''
        except KeyError:
            loaded_UUID = ''

        self.device = Agent.Device(self.device_name, dev_uuid=loaded_UUID)
        self.cache_facts()


        self.run_in_thread(self.start_server)
        self.run_in_thread(self.start_controller())

        atexit.register(logging.info, 'OnyxManager Master v%s - Stopped', '0.0.6')
        atexit.register(self.server.shutdown())
        atexit.register(self.commander.shutdown())

    def cache_facts(self):
        try:
            self.device.dump_facts_as_json(self.config['ProgramDirectory'] + utils.os_slash() + 'master.facts')
            logging.info('Device facts dumped to \'%s\'',
                         self.config['ProgramDirectory'] + utils.os_slash() + 'master.facts')
        except Exception as e:
            logging.error('Error: %s', e)
            raise e

    def start_server(self):
        if not os.path.isdir(self.config['KeyDirectory']):
            os.mkdir(self.config['KeyDirectory'])
        utils.create_self_signed_cert(self.config['KeyDirectory'], 'onyxmanager_master.crt', 'onyxmanager_master.key')
        self.server = utils.OnyxTCPServer(('', int(self.config['Port'])),
                                          utils.OnyxTCPHandler,
                                          self.config['KeyDirectory'] + utils.os_slash() + 'onyxmanager_master.crt',
                                          self.config['KeyDirectory'] + utils.os_slash() + 'onyxmanager_master.key')
        self.server.serve_forever()

    def start_controller(self):
        self.commander = utils.DeamonCommandServer(('', 27068), utils.DaemonHandler)
        self.commander.serve_forever()

    def run_in_thread(self, func, *args, **kwargs):
        t = threading.Thread(target=func, args=args, kwargs=kwargs)
        t.daemon = True
        self.threads.append(t)
        t.start()