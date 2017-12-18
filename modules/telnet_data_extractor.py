#!/usr/bin/env python3.5
# -*-coding:UTF-8 -*

'''
This script:
- extract all telnet data from pcap (do not parse the complete session)
'''

from abstract_module import AbstractModule

class Telnet_data_extractor(AbstractModule):
    # available function: publish(content), fields_from_tshark(fields)
    def process(self):
        filter_out = []

        # get wanted fields from tshark
        fields = ['ip.src', 'ip.dst', 'timestamp', 'telnet.data']
        #jsonRep = self.raw_command('tshark -r {} -T ek -e ip.src -e ip.dst'.format(self.current_filename), fields)
        jsonRep = self.fields_from_tshark(fields)

        ret = []
        set_telnet_data = set()
        # for each packet
        for packet_json in jsonRep:
            telnet_data = packet_json.get('telnet.data')

            if telnet_data not in set_telnet_data: # uniq ip_src
                set_telnet_data.add(telnet_data)
                ret.append({ 
                    'ips_src': packet_json['ip.src'],
                    'ips_dst': packet_json['ip.dst'],
                    'telnet_data': telnet_data,
                    'timestamp': packet_json['timestamp']
                })

        return ret

if __name__ == '__main__':
    script_name = __file__.split('/')[-1].split('.')[0] # filename without path
    config_path = '/home/sami/git/pcap-to-zmq/config.json'
    Telnet_data_extractor(config_path, module_name=script_name)
