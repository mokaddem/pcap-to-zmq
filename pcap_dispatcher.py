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

def dispath_pcap(serv, filename):
    #serv.lpush('Ip_src_extractor', filename)
    for module in all_modules:
        serv.lpush(module, filename)

def main(args):
    # setup redis connection
    serv = redis.StrictRedis(
            host = args.host,
            port = args.port,
            db   = args.db)
    
    logging.basicConfig(filename=args.logPath, filemode='a', level=logging.INFO)
    logger = logging.getLogger('pcap_dispatcher')
    rpcap = Redis_pcap(serv)

    config = json.load(args.config)
    for module in config['to_start']:
        all_modules.append(module)

    # main loop popping filename from redis queue
    while True:
        filename = serv.rpop(args.queue)
        if filename is None:
            logger.debug('No filename cap to process. Sleeping')
            time.sleep(args.sleepTime)
            continue
        filename = filename.decode('utf8')

        # cap should be put in redis
        if args.memory:
            logger.debug('Injecting in redis: {}'.format(filename))
            keyname = rpcap.put_cap_in_memory(filename)
            dispath_pcap(serv, 'redis_key:{}'.format(keyname))
        else: 
            logger.debug('Sending filename: {}'.format(filename))
            dispath_pcap(serv, filename)




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pops filenames from a redis queue, and forward it to python processor modules.')
    parser.add_argument('-q', '--queue', required=True, help='The queue name in redis')
    parser.add_argument('-c', '--config', required=True, type=open, help='The configuration file path')
    parser.add_argument('--host', required=False, default='localhost', help='The redis server hostname to connect to')
    parser.add_argument('-p', '--port', required=False, default=6379, type=int, help='The redis server port to connect to')
    parser.add_argument('-d', '--db', required=False, default=0, type=int, help='The redis server database number to connect to')
    parser.add_argument('-m', '--memory', required=False, action='store_true', help='Puts pcap in redis instead of letting module reading it. Allow faster processing for subsequent module at the cost of memory et injection time')
    parser.add_argument('-l', '--logPath', required=False, default=os.path.realpath(__file__), help='The configuration file path')
    parser.add_argument('-s', '--sleepTime', required=False, default=1, help='The time between each check for new filename in the queue')
    args = parser.parse_args()
    
    main(args)

