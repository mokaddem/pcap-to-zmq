#!/usr/bin/env python3.6
# -*-coding:UTF-8 -*

'''
Abstract class that all processing module should extend
'''

from abc import ABCMeta, abstractmethod
import os, sys, time, json
from subprocess import PIPE, Popen, check_output
import logging
import redis


class AbstractModule(metaclass=ABCMeta):
    def __init__(self, host, port, db, module_name='name', channelPublish='channel_results'):
        self.module_name = module_name
        self.module_queue_name = self.__class__.__name__
        self.channelPublish = channelPublish
        self.current_filename = None

        self.logger = logging.getLogger('logger_'+self.module_queue_name)
        handler = logging.FileHandler('log_'+self.module_queue_name, 'a')
        self.logger.addHandler(handler)
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)
        self.logger.addHandler(ch)

        self.serv = redis.StrictRedis(
                host = host,
                port = port,
                db = db)
        self.pop_and_process()

    def pop_and_process(self):
        self.logger.debug('queue name:', self.module_queue_name)
        while True:
            filename = self.serv.rpop(self.module_queue_name)
            if filename is None:
                self.logger.debug('no filename, sleeping')
                time.sleep(5)
                continue
            filename = filename.decode('utf8')
            self.current_filename = filename
            t1 = time.time()
            to_publish = self.process()
            self.logger.debug('took:', time.time()-t1)

            for item in to_publish:
                self.publish(item)
                self.logger.debug(item)


    # publish to redis pubsub
    def publish(self, content):
        to_publish = { 'module_name': self.module_name, 'content': content }
        self.serv.publish(self.channelPublish, json.dumps(to_publish))

    # get fields from tshark using the -e argument
    def fields_from_tshark(self, fields_list):
        tshark_command = ['tshark',  '-r',  self.current_filename, '-T', 'ek']
        # generate command to send with correct fields filter
        for f in fields_list:
            tshark_command += ['-e', f]
    
        p = Popen(tshark_command, stdin=PIPE, stdout=PIPE) 
    
        to_return = []
        for raw_resp in p.stdout:
            # ignore empty lines
            if raw_resp == b'\n':
                continue
            # ignore index lines
            if raw_resp[:10] == b'{"index" :':
                continue
    
            json_resp = json.loads(raw_resp.decode('utf8'))
            dico = {}
            for f in fields_list:
                json_layer = json_resp['layers']
                key = f.replace('.', '_') # json key do not contain '.' they are replaced by '_'
                dico[f] = json_layer[key][0] # wanted value is in an array, take the 1 element
            to_return.append(dico)
        return to_return

    # execute a raw (string) command
    def raw_command(self, cmd):
        command = [ c for c in cmd.split()]
        if 'tshark' not in command:
            self.logger.warning('The command {} does not call tshark'.format(command))
            return ""

        p = Popen(tshark_command, stdin=PIPE, stdout=PIPE) 
    
        to_return = []
        for raw_resp in p.stdout:
            # ignore empty lines
            if raw_resp == b'\n':
                continue
            # ignore index lines
            if raw_resp[:10] == b'{"index" :':
                continue
    
            json_resp = json.loads(raw_resp.decode('utf8'))
            dico = {}
            for f in fields_list:
                json_layer = json_resp['layers']
                key = f.replace('.', '_') # json key do not contain '.' they are replaced by '_'
                dico[f] = json_layer[key][0] # wanted value is in an array, take the 1 element
            to_return.append(dico)
        return to_return

    @abstractmethod
    # Must return a iterable data structure where its element will be pushed to zmq 
    def process(self):
        pass
