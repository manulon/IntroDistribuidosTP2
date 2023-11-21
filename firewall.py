from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
import json

from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt

log = core.getLogger()

class Firewall(EventMixin) :
    def __init__ ( self ) :
        self.listenTo(core.openflow)
        config = self.read_config("rules.json")
        self.firewall_switch = config["firewall_switch"]
        self.rules = config["rules"]
        log.debug("Enabling Firewall Module")
    
    def _handle_ConnectionUp(self, event):
        if event.dpid == self.firewall_switch:
            for rule in self.rules:
                if rule["enabled"]:
                    log.info(rule["msg"])
                    for r in rule["rule"]:
                        self.add_rule(event, r)

    def add_rule(self, event, rule):
        block_match = of.ofp_match()
        
        if "ip_type" in rule:
            block_match.dl_type = self.add_ip_type_rule(rule["ip_type"])
    
        if "protocol" in rule:
            block_match.nw_proto = self.add_protocol_rule(rule["protocol"])

        if "src_ip" in rule:
            block_match.nw_src = self.add_src_ip_rule(rule["src_ip"])

        if "dst_port" in rule:
            block_match.tp_dst = self.add_dst_port_rule(rule["dst_port"])

        if "src_mac" in rule:
            block_match.dl_src = self.add_mac_rule(rule["src_mac"])

        if "dst_mac" in rule:
            block_match.dl_dst = self.add_mac_rule(rule["dst_mac"])

        msg = of.ofp_flow_mod()
        msg.match = block_match
        event.connection.send(msg)

    def add_ip_type_rule(self, ip_type):
        if "ipv4" == ip_type:
            return pkt.ethernet.IP_TYPE
        if "ipv6" == ip_type:
            return pkt.ethernet.IPV6_TYPE

    def add_protocol_rule(self, protocol):
        network_protocols = {
            "tcp": pkt.ipv4.TCP_PROTOCOL,
            "udp": pkt.ipv4.UDP_PROTOCOL,
            "icmp": pkt.ipv4.ICMP_PROTOCOL,
        }

        return network_protocols[protocol]

    def add_dst_port_rule(self, dst_port):
        return dst_port
    
    def add_src_ip_rule(self, src_ip):
        return IPAddr(src_ip)
    
    def add_mac_rule(self, mac_addr):
        return EthAddr(mac_addr)

    def read_config(self, config_file):
        f = open (config_file, "r")
        config = json.loads(f.read())
        f.close()
        return config

def launch():
    # Starting the Firewall module
    core.registerNew(Firewall)