#!/usr/bin/env python3.6
# -*-coding:UTF-8 -*

'''
This program pops filename from a redis queue, and forward it to python processor modules.
'''

import redis
import json
import time
import logging
import argparse
import datetime
from pprint import pprint
import os

def dispath_pcap(filename):
    pass
    '''
    for module in all_modules:
        module.process(filename)
    '''

def main(args):
    # setup redis connection
    serv = redis.StrictRedis(
            host = args.host,
            port = args.port,
            db   = args.d)
    
    logging.basicConfig(filename=args.logPath, filemode='a', level=logging.INFO)
    logger = logging.getLogger('pcap_dispatcher')

    # main loop popping filename from redis queue
    while True:
        filename = serv.rpop(args.queue)
        if filename is None:
            logger.debug('Processed {} message(s) since last sleep.'.format(numMsg))
            numMsg = 0
            time.sleep(args.sleepTime)
            continue
        filename = filename.decode('utf8')
        dispath_pcap(filename)




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pops filenames from a redis queue, and forward it to python processor modules.')
    parser.add_argument('-q', '--queue', required=True, help='The queue name in redis')
    parser.add_argument('-h', '--host', required=False, default='localhost', help='The redis server hostname to connect to')
    parser.add_argument('-p', '--port', required=False, default=6379, type=int, help='The redis server port to connect to')
    parser.add_argument('-d', '--db', required=False, default=0, type=int, help='The redis server database number to conenct to')
    parser.add_argument('-c', '--config', required=False, help='The configuration file path')
    parser.add_argument('-l', '--logPath', required=False, default=os.path.realpath(__file__), help='The configuration file path')
    parser.add_argument('-s', '--sleepTime', required=False, default=1, help='The time between each check for new filename in the queue')
    args = parser.parse_args()
    
    main(args)

