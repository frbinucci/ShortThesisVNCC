# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4

import Constants

class MySwitchAndRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MySwitchAndRouter, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.external_port_counter={}
        self.port_mapper = {}
        self.nat_routing_parameters={}
        Constants.arp_association[Constants.R1_EXTERNAL_IP] = Constants.R1_EXTERNAL_MAC
        Constants.arp_association[Constants.R2_EXTERNAL_IP] = Constants.R2_EXTERNAL_MAC


    def add_flow(self, datapath, in_port, dst, src, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if dpid!=3 and dpid!=4 and dpid!=8:
            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                # ignore lldp packet
                return
            dst = eth.dst
            src = eth.src
            self.mac_to_port.setdefault(dpid, {})

            self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = msg.in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, msg.in_port, dst, src, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            datapath.send_msg(out)
        '''
        else:
            #Handling arp protocol
            if eth.ethertype== ether_types.ETH_TYPE_ARP:
                self.receive_arp(datapath, pkt, eth, msg.in_port)
                return 0
            else:
                ip4 = pkt.get_protocol(ipv4.ipv4)
                if dpid==3 :
                    if '10.0.1' in ip4.src and ip4.dst!='10.0.3.1':
                        match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_src='10.0.1.0', nw_src_mask=24,nw_dst = ip4.dst)
                        mod = datapath.ofproto_parser.OFPFlowMod(
                            datapath=datapath, match=match, cookie=0,
                            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                            priority=ofproto.OFP_DEFAULT_PRIORITY,
                            flags=ofproto.OFPFF_SEND_FLOW_REM)
                        datapath.send_msg(mod)
                        return
                    else:
                            if '10.0.3' in ip4.dst:
                                if ip4.dst not in Constants.arp_association.keys():
                                    self.send_arp(datapath, 1, Constants.GW_3_MAC, Constants.GW_3_IP, Constants.BROADCAST_MAC, ip4.dst, 3)
                                    if '10.0.1' not in ip4.src:
                                        prefix = ip4.src.split(".")
                                        for i in range(0,len(prefix)-1):
                                            prefix[i]=prefix[i]+"."
                                        prefix[3] = '0'
                                        net_address = "".join(prefix)
                                        match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_src=net_address,nw_src_mask=24, nw_dst='10.0.3.0',nw_dst_mask=24)
                                        mod = datapath.ofproto_parser.OFPFlowMod(
                                            datapath=datapath, match=match, cookie=0,
                                            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                                            priority=ofproto.OFP_DEFAULT_PRIORITY,
                                            flags=ofproto.OFPFF_SEND_FLOW_REM)
                                        datapath.send_msg(mod)
                            elif '10.0.1' in ip4.dst:
                                    if '10.0.3' not in ip4.src:
                                        prefix = ip4.src.split(".")
                                        for i in range(0,len(prefix)-1):
                                            prefix[i]=prefix[i]+"."
                                        prefix[3] = '0'
                                        net_address = "".join(prefix)
                                        match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_src=net_address,nw_src_mask=24, nw_dst='10.0.1.0',nw_dst_mask=24)
                                        mod = datapath.ofproto_parser.OFPFlowMod(
                                            datapath=datapath, match=match, cookie=0,
                                            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                                            priority=ofproto.OFP_DEFAULT_PRIORITY,
                                            flags=ofproto.OFPFF_SEND_FLOW_REM)
                                        datapath.send_msg(mod)
                                    if ip4.dst not in Constants.arp_association.keys():
                                        self.send_arp(datapath, 1, Constants.GW_1_MAC, Constants.GW_1_IP, Constants.BROADCAST_MAC, ip4.dst, 1)
                            elif '10.0.2' in ip4.dst:
                                if ip4.dst not in Constants.arp_association.keys():
                                    self.send_arp(datapath, 1, Constants.GW_2_MAC, Constants.GW_2_IP, Constants.BROADCAST_MAC, ip4.dst, 2)
                            elif '10.1' in ip4.dst:
                                if Constants.arp_association.get(Constants.R2_ROUTING_IP)==None:
                                    self.send_arp(datapath,1,Constants.R1_ROUTING_MAC,Constants.R1_ROUTING_IP,Constants.BROADCAST_MAC,Constants.R2_ROUTING_IP,5)

                            #Checking packet source for arp resolution
                            if '10.0.2' in ip4.src:
                                self.send_arp(datapath, 1, Constants.GW_2_MAC, Constants.GW_2_IP, Constants.BROADCAST_MAC, ip4.src, 2)
                            if '10.0.1' in ip4.src:
                                self.send_arp(datapath, 1, Constants.GW_1_MAC, Constants.GW_1_IP, Constants.BROADCAST_MAC, ip4.src, 1)
                            if '10.0.3' in ip4.src:
                                self.send_arp(datapath, 1, Constants.GW_3_MAC, Constants.GW_3_IP, Constants.BROADCAST_MAC, ip4.src, 3)
                elif dpid==4:
                    if '10.0' in ip4.dst:
                        if Constants.arp_association.get(Constants.R1_ROUTING_IP)==None:
                            self.send_arp(datapath,1,Constants.R2_ROUTING_MAC,Constants.R2_ROUTING_IP,Constants.BROADCAST_MAC,Constants.R1_ROUTING_IP,1)
                    elif '10.1' in ip4.dst:
                        if ip4.dst not in Constants.arp_association.keys():
                            self.send_arp(datapath, 1, Constants.GW_4_MAC, Constants.GW_4_IP, Constants.BROADCAST_MAC, ip4.dst, 2)
                    if '10.1' in ip4.src:
                        self.send_arp(datapath, 1, Constants.GW_4_MAC, Constants.GW_4_IP, Constants.BROADCAST_MAC, ip4.src, 2)
                elif dpid==8:
                    if '8.8.8' in ip4.dst:
                        if Constants.arp_association.get(ip4.dst)==None:
                            self.send_arp(datapath,1,Constants.GATEWAY_FOR_INTERNET_MAC,Constants.GATEWAY_FOR_INTERNET_IP,Constants.BROADCAST_MAC,ip4.dst,1)
                    else:
                        if Constants.R1_EXTERNAL_IP in ip4.dst:
                            self.install_gw_rule(datapath,Constants.R1_EXTERNAL_IP,Constants.R1_EXTERNAL_GATEWAY_MAC,2)
                        elif Constants.R2_EXTERNAL_IP in ip4.dst:
                            self.install_gw_rule(datapath,Constants.R2_EXTERNAL_IP,Constants.R2_EXTERNAL_GATEWAY_MAC,3)
            return 1'''

    '''def install_gw_rule(self,datapath,nw_dst,hw_addr,out_port,**kwargs):
        ofproto = datapath.ofproto
        mask = kwargs.get('mask',None)
        true_dest = kwargs.get('true_dest',None)
        if true_dest == None:
            true_dest = nw_dst
        match = None
        if mask==None:
            match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_dst=true_dest)
        else:
            match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_dst=true_dest,nw_dst_mask=mask)

        actions = [
            datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(Constants.arp_association[nw_dst])),
            datapath.ofproto_parser.OFPActionSetDlSrc(haddr_to_bin(hw_addr)),
            datapath.ofproto_parser.OFPActionOutput(out_port)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)'''

    ####################################################################################################################
    ######FUNCTIONS USED IN ORDER TO MANAGE ARP IMPLEMENTATION##########################################################
    ####################################################################################################################
    '''def receive_arp(self, datapath, packet, etherFrame, inPort):
        arpPacket = packet.get_protocol(arp.arp)
        if arpPacket.opcode == 1:
            arp_dstIp = arpPacket.dst_ip
            self.logger.info("receive ARP request %s => %s (port%d)"
                       %(etherFrame.src, etherFrame.dst, inPort))
            self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, inPort)
        elif arpPacket.opcode == 2:
            Constants.arp_association[arpPacket.src_ip]=arpPacket.src_mac
            if datapath.id==3:
                if '10.0.1' in arpPacket.src_ip:
                    self.install_gw_rule(datapath,arpPacket.src_ip,'00:00:00:00:00:10',1)
                elif '10.0.3' in arpPacket.src_ip:
                    self.install_gw_rule(datapath,arpPacket.src_ip,'00:00:00:00:00:12',3)
                elif '10.0.2' in arpPacket.src_ip:
                    self.install_gw_rule(datapath,arpPacket.src_ip,'00:00:00:00:00:11',2)
                elif '192.168.0' in arpPacket.src_ip:
                    self.install_gw_rule(datapath, arpPacket.src_ip, '00:00:00:00:00:13', 5,mask=16,true_dest='10.1.0.0')
            elif datapath.id==4:
                if '10.1.5' in arpPacket.src_ip:
                    self.install_gw_rule(datapath,arpPacket.src_ip,'00:00:00:00:00:15',2)
                elif '192.168.0' in arpPacket.src_ip:
                    self.install_gw_rule(datapath,arpPacket.src_ip,'00:00:00:00:00:14',1,mask=16,true_dest='10.0.0.0')
            elif datapath.id==8:
                if '8.8.8' in arpPacket.src_ip:
                    self.install_gw_rule(datapath,arpPacket.src_ip,Constants.GATEWAY_FOR_INTERNET_MAC,1)

    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort):
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src
        srcMac= ''
        outPort = ''

        if arp_dstIp == Constants.GW_1_IP:
            srcMac = Constants.GW_1_MAC
            outPort = 1
        elif arp_dstIp == Constants.GW_2_IP:
            srcMac = Constants.GW_2_MAC
            outPort = 2
        elif arp_dstIp == Constants.GW_3_IP:
            srcMac = Constants.GW_3_MAC
            outPort = 3
        elif arp_dstIp == Constants.GW_4_IP:
            srcMac = Constants.GW_4_MAC
            outPort = 2
        elif arp_dstIp == Constants.R2_ROUTING_IP:
            srcMac = Constants.R2_ROUTING_MAC
            outPort = 1
        elif arp_dstIp == Constants.R1_ROUTING_IP:
            srcMac = Constants.R1_ROUTING_MAC
            outPort = 5
        elif arp_dstIp==Constants.GATEWAY_FOR_INTERNET_IP:
            srcMac = Constants.GATEWAY_FOR_INTERNET_MAC
            outPort = 1

        else:
            self.logger.info("unknown arp request received !")

        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
        self.logger.info("send ARP reply %s => %s (port%d)" %(srcMac, dstMac, outPort))


    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        self.logger.info("Eth data: dstMac: %s,srcMac: %s, type: %s",dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        self.logger.info("ARP DATA: opcode: %s, src mac: %s, src ip: %s, target mac: %s, target ip: %s",opcode,srcMac,srcIp, targetMac, targetIp)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)'''
    ####################################################################################################################
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)