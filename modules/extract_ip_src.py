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
        fields = ['ip.src', 'ip.dst']
        jsonRep = self.fields_from_tshark(fields)

        ret = []
        set_ip_src = set()
        # for each packet
        for packet_json in jsonRep:
            ip_src = packet_json[fields[0]]
            ip_dst = packet_json[fields[1]]

            if ip_src not in filter_out: # filtering
                 if ip_src not in set_ip_src: # uniq ip_src
                    set_ip_src.add(ip_src)
                    ret.append({ 
                            'ips_src': ip_src,
                            'ips_dst': ip_dst,
                            })
        return ret
