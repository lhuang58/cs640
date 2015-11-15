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

class PacketInQueue(object):
    def __init__(self, packet, time):
        self.packet = packet
        self.time = time
        self.retry = 0

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
        pktsQueue = []
        forwardingTable = []
        f = open('forwarding_table.txt', 'r')
        # Build the forwarding table from file
        for line in f:
            temp = line.strip().split(' ')
            forwardingTable.append(temp)
        f.close()

        etherIpMap = {} # ethernet/IP mapping
        ipIntfMap = {} # ip/interfaces mapping

        # Build the forwarding table from interfaces
        for intf in interfaces:
            print(intf)
            ipIntfMap[str(intf.ipaddr)] = intf
            networkPrefix = IPv4Address(int(intf.ipaddr) & int(intf.netmask))
            forwardingTable.append([str(networkPrefix), str(intf.netmask), str(intf.ipaddr), intf.name])

        while True:
            gotpkt = True
            try:
                dev,pkt = self.net.recv_packet(timeout=1.0)
                arp = pkt.get_header(Arp)

            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))

                etherHeader = Ethernet()
                # If the pkt is not an arp packet, then start processing the pkt
                if arp is None:
                    # add the pkt to the queue
                    pktsQueue.append(PacketInQueue(pkt, time.time()))

                    pkt[1].ttl -= 1 # decrement TTL by 1
                    maxPrefixLen = 0
                    dstIpAddr = pkt[1].dst
                    nextHop = None
                    etherHeader.src = pkt[0].src
                    etherHeader.ethertype = EtherType.IPv4
                    # Look up forwarding table
                    for entry in forwardingTable:
                        prefix = IPv4Address(entry[0])
                        subnetMask = IPv4Address(entry[1])
                        dstSubnetNumber = IPv4Address(int(dstIpAddr) & int(subnetMask))
                        matches = (int(prefix) & int(dstSubnetNumber)) == int(prefix)
                        tempPrefixLength = IPv4Network(str(prefix) + '/' + str(subnetMask)).prefixlen
                        # Check prefix length
                        if matches and tempPrefixLength > maxPrefixLen:
                            maxPrefixLen = tempPrefixLength
                            nextHop = entry[2]
                    # If there is a match for this and the destination address is not
                    # one of addresses in router's interfaces, then send the request for destination host
                    if nextHop is not None and str(dstIpAddr) not in ipIntfMap.keys():
                        # Send the ARP request to the host where IP address need to be resovled
                        if etherIpMap.get(str(dstIpAddr)) is None:
                            temp = ipIntfMap.get(nextHop)
                            senderhwaddr = temp.ethaddr
                            senderprotoaddr = temp.ipaddr
                            request = create_ip_arp_request(senderhwaddr, senderprotoaddr, dstIpAddr)
                            self.net.send_packet(temp.name, request)
                else:
                # The pkt is an arp pkt, then complete the header and forward the ip pkt
                # if the arp pkt is an request, then send the reply
                    print("arp: ")
                    print(arp.targethwaddr)
                    if ipIntfMap.get(str(arp.targetprotoaddr)) is not None:
                        requestIntf = ipIntfMap[str(arp.targetprotoaddr)]
                        if str(arp.targethwaddr) != "ff:ff:ff:ff:ff:ff":
                            if arp.senderhwaddr not in etherIpMap.keys():
                                etherHeader.dst = arp.senderhwaddr
                                #store the sender ip/ethernet map
                                etherIpMap[str(arp.senderprotoaddr)] = arp.senderhwaddr
                            pktToSend = pktsQueue.pop(0).packet
                            etherHeader.src = requestIntf.ethaddr
                            pktToSend[0] = etherHeader
                            # store receiver IP/Ethernet map
                            etherIpMap[str(requestIntf.ipaddr)] = requestIntf.ethaddr
                            self.net.send_packet(requestIntf.name, pktToSend)
                        else:
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
