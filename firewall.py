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
                    log.debug(rule["enabled"])
                    self.add_rule(event, rule["rule"])
                    log.debug("Firewall rule: %s installed on switch %s", rule["name"], dpidToStr(event.dpid))

    def add_rule(self, event, rule):
        block_match = of.ofp_match()
        
        if "dst_port" in rule:
            block_match.tp_dst = rule["dst_port"]

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