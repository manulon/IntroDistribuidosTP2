# from tkinter import N
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
import json

log = core.getLogger()

class SDNFirewall(EventMixin):
    def __init__ (self, h1, h2):
        self.h1 = h1
        self.h2 = h2
        self.listenTo(core.openflow)
        self.rules = self._load_configuration()
    
    def _load_configuration(self):
        with open("firewall.rules", "r") as f:
            return json.load(f)
            
    def _handle_PacketIn(self,event):
        l2_packet = event.parsed
        if (l2_packet.type != ethernet.IP_TYPE):
            return

        if (self.verify_rules(l2_packet) == True):
            self.drop_packet(event)

    def verify_dstport_80(self, l2_packet):
        if self.rules["rule_1.enabled"] == False:
            log.info("La regla 1 se encuentra desactivada.")
            return False

        l3_packet = l2_packet.payload
        if (l3_packet.protocol == ipv4.TCP_PROTOCOL or l3_packet.protocol == ipv4.UDP_PROTOCOL):
            l4_packet = l3_packet.payload
            if (l4_packet.dstport == 80):
                log.info("Se dropea un paquete por tener como destino puerto 80.")

                return True
        return False
    
    def verify_h1_udp_5001(self, l2_packet):
        if self.rules["rule_2.enabled"] == False:
            log.info("La regla 2 se encuentra desactivada.")
            return False

        l3_packet = l2_packet.payload
        if (l3_packet.protocol == ipv4.TCP_PROTOCOL or l3_packet.protocol == ipv4.UDP_PROTOCOL):
            l4_packet = l3_packet.payload

            host1_ip = self.rules["rule_2.blocked_host"]
            if (l4_packet.dstport == 5001 and l3_packet.srcip == host1_ip and l3_packet.protocol == ipv4.UDP_PROTOCOL):
                log.info("Se dropea un paquete por tener como destino puerto 5001, ser proveniente del host 1 (IP: %s) y ser de UDP." % (host1_ip))

                return True
        return False
    
    def verify_uncommunicated_hosts(self, l2_packet):
        if self.rules["rule_3.enabled"] == False:
            log.info("La regla 3 se encuentra desactivada.")
            return False

        l3_packet = l2_packet.payload
        if ((l3_packet.srcip == self.h1 and l3_packet.dstip == self.h2 ) or 
            (l3_packet.srcip == self.h2 and l3_packet.dstip == self.h1)):
            log.info("Se dropea un paquete de origen: %s, Destino: %s. Los hosts estan incomunicados." % (l3_packet.srcip, l3_packet.dstip))
            
            return True
        return False

    def verify_rules(self,l2_packet):
        if (self.verify_dstport_80(l2_packet)):
            return True
        if (self.verify_h1_udp_5001(l2_packet)):
            return True
        if (self.verify_uncommunicated_hosts(l2_packet)):
            return True

        return False
    
    def drop_packet(self,event):
        event.halt = True
        
        
def launch (first_host = None, second_host = None):
    core.registerNew(SDNFirewall,first_host,second_host)