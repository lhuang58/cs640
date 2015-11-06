#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        interfaces = self.net.interfaces()
        ipmap = {}
        for intf in interfaces:
            ipmap[str(intf.ipaddr)] = intf
        while True:
            gotpkt = True
            try:
                dev,pkt = self.net.recv_packet(timeout=1.0)
                arp = pkt.get_header(Arp)
                print("<------->")
                print(arp)

            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
            if arp is not None:
                if ipmap[str(arp.targetprotoaddr)] is not None:
                    requestIntf = ipmap[str(arp.targetprotoaddr)]
                    arpReply = create_ip_arp_reply(requestIntf.ethaddr, arp.senderhwaddr, requestIntf.ipaddr, arp.senderprotoaddr)
                    self.net.send_packet(requestIntf.name, arpReply)
def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
