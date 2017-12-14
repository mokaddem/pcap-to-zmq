#!/usr/bin/env python3.6
# -*-coding:UTF-8 -*

'''
This script:
- extract all ip-source addresses from a pcap and pass them through a filterlist
'''

from abstract_module import AbstractModule

class Ip_src_extractor(AbstractModule):
    # available function: publish(content), fields_from_tshark(fields)
    def process(self):
        filter_out = []

        # get wanted fields from tshark
        fields = ['ip.src', 'ip.dst', 'timestamp']
        #jsonRep = self.raw_command('tshark -r {} -T ek -e ip.src -e ip.dst'.format(self.current_filename), fields)
        jsonRep = self.fields_from_tshark(fields)

        ret = []
        set_ip_src = set()
        # for each packet
        for packet_json in jsonRep:

            if packet_json['ip.src'] not in filter_out: # filtering
                 if packet_json['ip.src'] not in set_ip_src: # uniq ip_src
                    set_ip_src.add(ip_src)
                    ret.append({ 
                            'ips_src': packet_json['ip.src'],
                            'ips_dst': packet_json['ip.dst'],
                            'timestamp': packet_json['timestamp']
                            })
        return ret
