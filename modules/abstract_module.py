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
        self.rpcap = Redis_pcap(self.serv)

        self.pop_and_process()

    def pop_and_process(self):
        self.logger.debug('queue name:', self.module_queue_name)
        while True:
            filename = self.serv.rpop(self.module_queue_name)

            # check if a filename is in the queue
            if filename is None:
                self.logger.debug('no filename, sleeping')
                time.sleep(5)
                continue

            filename = filename.decode('utf8')
            # check if the file is in memory are in redis 
            if filename.startswith('redis_key:'):
                # remove key header
                self.capInRedis = True
                self.redis_key = filename.replace('redis_key:', '')
            else:
                self.capInRedis = False
                self.redis_key = None
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

    def get_field_from_ek(self, json_layer, field):
        fields_list = field.split('.')
        ret = json_layer
        pre_pend = ''
        for f in fields_list:
            ret = ret[pre_pend+f]
            pre_pend += '{}_{}_'.format(f, f)
        return ret

    # get fields from tshark using the -e argument
    def fields_from_tshark(self, fields_list):
        to_return = []

        # if the cap file is already in memory
        if self.capInRedis:
            dico = {}
            for json_packet in self.rpcap.get_cap_from_memory(self.redis_key):
                json_layer = json_packet['layers']
                for f in fields_list:
                    key = f.replace('.', '_') # json key do not contain '.' they are replaced by '_'
                    dico[f] = self.get_field_from_ek(json_layer, f)
                to_return.append(dico)

        else:
            tshark_command = ['tshark',  '-r',  self.current_filename, '-T', 'ek']
            # generate command to send with correct fields filter
            for f in fields_list:
                tshark_command += ['-e', f]

            p = Popen(tshark_command, stdin=PIPE, stdout=PIPE) 
    
            for raw_resp in p.stdout:
                # ignore empty lines
                if raw_resp == b'\n':
                    continue
                # ignore index lines
                if raw_resp[:10] == b'{"index" :':
                    continue
    
                # done in loop for faster processing
                json_resp = json.loads(raw_resp.decode('utf8'))
                dico = {}
                json_layer = json_resp['layers']
                for f in fields_list:
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


class Redis_pcap:
    def __init__(self, serv):
        self.serv = serv

    def put_cap_in_memory(self, filename):
        tshark_command = ['tshark',  '-r',  filename, '-T', 'ek']
        p = Popen(tshark_command, stdin=PIPE, stdout=PIPE) 
    
        keyname = '{timestamp}:{filename}'.format(timestamp=time.time(), filename=filename)
        for raw_resp in p.stdout:
            # ignore empty lines
            if raw_resp == b'\n':
                continue
            # ignore index lines
            if raw_resp[:10] == b'{"index" :':
                continue
    
            json_resp = json.loads(raw_resp.decode('utf8'))
            self.serv.rpush(keyname, json.dumps(json_resp))
        return keyname


    def get_cap_from_memory(self, keyname):
        packets = []
        for packet_raw in self.serv.lrange(keyname, 0, -1):
            packet_json = json.loads(packet_raw.decode('utf8'))
            packets.append(packet_json)
        return packets
