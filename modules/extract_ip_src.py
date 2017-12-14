#!/usr/bin/env python3.6
# -*-coding:UTF-8 -*

'''
This script:
- extract all ip-source addresses from a pcap and pass them through a filterlist
'''

from abstract_module import AbstractModule

class ip_src_extractor(AbstractModule):
    # available function: publish(content), fields_from_tshark(fields)
    def process(self):
        filter_out = []

        # get wanted fields from tshark
        fields = ['ip.src']
        jsonRep = self.fields_from_tshark(fields)

        set_ip = set()
        # for each packet
        for packet_json in jsonRep:
            ip = packet_json[fields[0]]
            if ip not in filter_out:
                set_ip.add(ip)

        return set_ip
