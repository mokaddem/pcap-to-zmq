#!/usr/bin/env python3.6
# -*-coding:UTF-8 -*

'''
Abstract class that all processing module should extend
'''

from abc import ABCMeta, abstractmethod
import logging
import redis


class AbstractModule(metaclass=ABCMeta):
    def __init__(self, host, port, db, module_name='name', channelPublish='channel_results'):
        self.module_queue_name = __name__
        self.channelPublish = channelPublish

        self.logger = logging.getLogger('logger_'+self.module_queue_name)
        self.logger.basicConfig(filename='log_'+self.module_queue_name, filemode='a', level=logging.INFO)

        self.serv = redis.StrictRedis(
                host = host,
                port = port,
                db = db)

    def pop_and_process(self):
        filename = self.serv.rpop(self.module_queue_name)
        if filename is None:
            time.sleep(5)
            continue
        filename = filename.decode('utf8')
        self.process(filename)

    def publish_zmq(self, content):
        to_publish = { 'module_name': self.module_name, 'content': content }
        self.serv.publish(self.channelPublish, json.dumps(to_publish))

    @abstractmethod
    def process(self):
        pass
