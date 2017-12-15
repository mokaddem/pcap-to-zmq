#!/usr/bin/env python3.5
# -*-coding:UTF-8 -*

'''
This program pops filename from a redis queue, and forward it to python processor modules.
# Should it read the pcap and put it into memory for faster re-use by other modules?
'''

import redis
import json
import time
import logging
import argparse
import datetime
import os, sys

sys.path.append('modules/')
from abstract_module import Redis_pcap

all_modules = []

class Struct:
    def __init__(self, **entries):
        self.__dict__.update(entries)

def dispath_pcap(serv, filename):
    for module in all_modules:
        serv.lpush(module, filename)

def main(args_commandline):
    config = json.load(args_commandline.config)
    for arg in vars(args_commandline):
        if arg == 'config':
            continue
        value = getattr(args_commandline, arg)
        if value is not None:
            config[arg] = value
    config = Struct(**config)

    logger = logging.getLogger('pcap_dispatcher')
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler('log_dispatcher', 'a')
    logger.addHandler(handler)

    # setup redis connection
    try:
        serv = redis.Redis(unix_socket_path=config.socket)
    except Exception as e:
        logger.warning('failed to use unix_socket for redis')
        serv = redis.StrictRedis(
                host = config.host,
                port = config.port,
                db   = config.db)
    
    rpcap = Redis_pcap(serv)

    # add module to module_list
    # start module inside a screen
    screen_name = 'pcap_dispatcher_modules'
    os.system('screen -X -S {} quit &>/dev/null'.format(screen_name))
    os.system('screen -dmS {}'.format(screen_name))
    for module in config.to_start:
        logger.info('starting {}'.format(module))
        all_modules.append(module)
        os.system("screen -S {screenName} -X screen -t '{moduleName}' bash -c './modules/{moduleName}.py; read x;'".format(screenName=screen_name, moduleName=module))

    # main loop popping filename from redis queue
    while True:
        filename = serv.rpop(config.queue)
        if filename is None:
            logger.debug('No filename cap to process. Sleeping')
            time.sleep(config.sleepTime)
            continue
        filename = filename.decode('utf8')

        # cap should be put in redis
        if config.memory:
            t1 = time.time()
            logger.info('Injecting in redis: {}'.format(filename))
            keyname = rpcap.put_cap_in_memory(filename)
            logger.info('Injection {} tooks: {}sec'.format(filename, str(int(t1-time.time()))))
            dispath_pcap(serv, 'redis_key:{}'.format(keyname))
        else: 
            logger.debug('Sending filename: {}'.format(filename))
            dispath_pcap(serv, filename)




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pops filenames from a redis queue, and forward it to python processor modules.')
    parser.add_argument('-c', '--config', required=True, type=open, help='The configuration file path')
    parser.add_argument('-q', '--queue', required=False, help='The queue name in redis')
    parser.add_argument('--host', required=False, help='The redis server hostname to connect to')
    parser.add_argument('-p', '--port', required=False, type=int, help='The redis server port to connect to')
    parser.add_argument('-d', '--db', required=False, type=int, help='The redis server database number to connect to')
    parser.add_argument('-m', '--memory', required=False, action='store_true', help='Puts pcap in redis instead of letting module reading it. Allow faster processing for subsequent module at the cost of memory et injection time')
    parser.add_argument('-l', '--logPath', required=False, help='The configuration file path')
    parser.add_argument('-s', '--sleepTime', required=False, help='The time between each check for new filename in the queue')
    args = parser.parse_args()
    
    main(args)

