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
                if rule.enabled:
                    self.add_rule(event, rule["rule"])
                    log.debug("Firewall rule: %s installed on switch %s", rule["name"], dpidToStr(event.dpid))

    def add_rule(self, event, rule):
        block_match = of.ofp_match()

        log.debug('block_match: %s', block_match)

        if "data_link" in rule:
            self.add_data_link_rule(rule["data_link"], block_match)
        if "network" in rule:
            self.add_network_rule(rule["network"], block_match)
        if "transport" in rule:
            self.add_transport_rule(rule["transport"], block_match)

        msg = of.ofp_flow_mod()
        log.debug('msg: %s', msg)
        log.debug('msg.match: %s', msg.match)
        msg.match = block_match
        event.connection.send(msg)

    def add_data_link_rule(self, rule, block_match):
        if "ip_type" in rule:
            if "ipv4" == rule["ip_type"]:
                block_match.dl_type = pkt.ethernet.IP_TYPE
            if "ipv6" == rule["ip_type"]:
                block_match.dl_type = pkt.ethernet.IPV6_TYPE
        if "mac" in rule:
            if "src" in rule["mac"]:
                block_match.dl_src = EthAddr(rule["mac"]["src"])
            if "dst" in rule["mac"]:
                block_match.dl_dst = EthAddr(rule["mac"]["dst"])

    def add_network_rule(self, rule, block_match):
        network_protocols = {
            "tcp": pkt.ipv4.TCP_PROTOCOL,
            "udp": pkt.ipv4.UDP_PROTOCOL,
            "icmp": pkt.ipv4.ICMP_PROTOCOL,
        }
        selected = rule["protocol"]
        if selected in network_protocols:
            block_match.nw_proto = network_protocols[selected]

        if "src_ip" in rule:
            block_match.nw_src = IPAddr(rule["src_ip"])
        if "dst_ip" in rule:
            block_match.nw_dst = IPAddr(rule["dst_ip"])

    def add_transport_rule(self, rule, block_match):
        if "src_port" in rule:
            block_match.tp_src = rule["src_port"]
        if "dst_port" in rule:
            block_match.tp_dst = rule["dst_port"]

    def read_config(self, config_file):
        f = open (config_file, "r")
        config = json.loads(f.read())
        f.close()
        return config

def launch():
    # Starting the Firewall module
    core.registerNew(Firewall)