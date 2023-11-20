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
                    self.add_rule(event, rule["rule"], rule["number"])

    def add_rule(self, event, rule, number):
        block_match = of.ofp_match()
        
        if number == 1:
            # La regla 1 esta activada
            log.warning("Se droperan paquetes con puerto de destino %s" % (rule["dst_port"]))
            if "dst_port" in rule:
                block_match.tp_dst = rule["dst_port"]

        elif number == 2:
            # La regla 2 esta activada
            log.warning("Se droperan paquetes de origen: %s, que sean UDP y que tengan como puerto: %s" % (rule["src_ip"], rule["dst_port"]))
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
            if "dst_port" in rule:
                block_match.tp_dst = rule["dst_port"]     

        elif number == 3:
            # La regla 3 esta activada
            log.warning("Se droperan paquetes de origen: %s, Destino: %s. Los hosts estan incomunicados." % (rule["src_ip"], rule["dst_ip"]))

            if "src_ip" in rule:
                block_match.nw_src = IPAddr(rule["src_ip"])
            if "dst_ip" in rule:
                block_match.nw_dst = IPAddr(rule["dst_ip"])

        msg = of.ofp_flow_mod()
        msg.match = block_match
        event.connection.send(msg)

    def read_config(self, config_file):
        f = open (config_file, "r")
        config = json.loads(f.read())
        f.close()
        return config

def launch():
    # Starting the Firewall module
    core.registerNew(Firewall)