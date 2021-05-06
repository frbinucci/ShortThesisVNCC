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
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu import cfg
import ipaddress
import Constants


class NAT(app_manager.RyuApp):

    def __init__(self,*args,**kwargs):
        super(NAT, self).__init__(*args, **kwargs)
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.StrOpt('nat_list', default=0, help = ('nat_list')),
            cfg.StrOpt('nat_external_ip_list',default=0, help=('nat_external_ip_list')),
            cfg.StrOpt('nat_external_gateway_list',default=0, help=('nat_external_gateway_list')),
            cfg.StrOpt('nat_external_mac_list',default=0, help=('nat_external_mac_list')),
            cfg.StrOpt('nat_external_gateway_mac_list',default=0, help=('nat_external_gateway_mac_list')),
            cfg.StrOpt('nat_external_port_list',default=0, help=('nat_external_port_list')),
            cfg.StrOpt('nat_internal_port_list',default=0, help=('nat_internal_port_list'))])
        self.nat_list = CONF.nat_list.split(",")
        self.external_ip_list = CONF.nat_external_ip_list.split(",")
        self.external_gateway_list = CONF.nat_external_gateway_list.split(",")
        self.external_mac_list = CONF.nat_external_mac_list.split(",")
        self.external_gateway_mac_list = CONF.nat_external_gateway_mac_list.split(",")
        self.nat_external_port_list = CONF.nat_external_port_list.split(",")
        self.nat_internal_port_list = CONF.nat_internal_port_list.split(",")

        self.logger.info(str(self.nat_list))
        self.external_port_counter={}
        self.nat_routing_parameters={}
        self.port_mapper = {}
        i=0
        for nat in self.nat_list:
            nat_index = int(nat)
            self.logger.info(nat_index)
            #self.external_port_counter[nat_index] = {}
            self.port_number_start = 2000
            self.port_number_stop = 65535
            for current_port in range(self.port_number_start,self.port_number_stop):
                self.external_port_counter[nat_index,current_port]=True
            self.nat_routing_parameters[nat_index]=(self.external_ip_list[i],
                                                    self.external_gateway_list[i],
                                                    self.external_mac_list[i],
                                                    self.external_gateway_mac_list[i],
                                                    int(self.nat_external_port_list[i]),
                                                    int(self.nat_internal_port_list[i]))
            i=i+1
        #self.nat_routing_parameters[4]=(Constants.R2_EXTERNAL_IP,Constants.R2_EXTERNAL_GATEWAY,Constants.R2_EXTERNAL_MAC,Constants.R2_EXTERNAL_GATEWAY_MAC,Constants.R2_EXTERNAL_PORT,Constants.R2_INTERNAL_PORT)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if str(dpid) in self.nat_list:
            ip4_pkt=pkt.get_protocol(ipv4.ipv4)
            if ip4_pkt!=None:
                if not ipaddress.ip_address(ip4_pkt.src.decode('utf-8')).is_private:
                    self.manage_nat(datapath, pkt, 'inbound')
                elif not ipaddress.ip_address(ip4_pkt.dst.decode('utf-8')).is_private and ip4_pkt.dst!='255.255.255.255':
                    self.manage_nat(datapath, pkt, 'outbound')
                else:
                    return

    def manage_nat(self,datapath,pkt,direction):

        ip4 = pkt.get_protocol(ipv4.ipv4)
        tcp4 = pkt.get_protocol(tcp.tcp)
        udp4 = pkt.get_protocol(udp.udp)

        if tcp4:
            src_port = tcp4.src_port
            dst_port = tcp4.dst_port
        elif udp4:
            src_port = udp4.src_port
            dst_port = udp4.dst_port
        else:
            self.logger.info("Protocol not supported yet!")
            return

        id = datapath.id
        src = ip4.src

        ofproto = datapath.ofproto

        my_mac = self.nat_routing_parameters[id][2]
        match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_proto=6, nw_src=ip4.src, nw_dst=ip4.dst,
                                                 tp_src=src_port, tp_dst=dst_port)
        if direction=='outbound':
            next_port = self.getNewAvailablePort(datapath.id)
            self.port_mapper[datapath.id, next_port] = (src, src_port)

            next_hop_mac = self.nat_routing_parameters[id][3]
            external_ip = self.nat_routing_parameters[id][0]
            out_port = self.nat_routing_parameters[id][4]
            actions = [
                datapath.ofproto_parser.OFPActionSetNwSrc(external_ip),
                datapath.ofproto_parser.OFPActionSetTpSrc(next_port),
                datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(next_hop_mac)),
                datapath.ofproto_parser.OFPActionSetDlSrc(haddr_to_bin(my_mac)),
                datapath.ofproto_parser.OFPActionOutput(out_port)]

            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=10, hard_timeout=0,
                priority=ofproto.OFP_DEFAULT_PRIORITY,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
            datapath.send_msg(mod)
        else:
            internal_address = self.port_mapper[datapath.id,dst_port][0]
            internal_port = self.port_mapper[datapath.id,dst_port][1]
            hw_address = Constants.arp_association[internal_address]
            out_port = self.nat_routing_parameters[id][5]

            actions = [
                datapath.ofproto_parser.OFPActionSetNwDst(internal_address),
                datapath.ofproto_parser.OFPActionSetTpDst(internal_port),
                datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(hw_address)),
                datapath.ofproto_parser.OFPActionSetDlSrc(haddr_to_bin(my_mac)),
                datapath.ofproto_parser.OFPActionOutput(out_port)]

            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=10, hard_timeout=0,
                priority=ofproto.OFP_DEFAULT_PRIORITY,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
            datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        tp_dst = int(msg.match.tp_dst)
        nw_dst = int(msg.match.nw_dst)
        dpid = msg.datapath.id
        if tp_dst>=self.port_number_start and tp_dst<=self.port_number_stop and ipaddress.ip_address(nw_dst)==ipaddress.ip_address(self.nat_routing_parameters[dpid][0].decode('utf-8')):
            self.external_port_counter[dpid,tp_dst]=True
            self.logger.info(">>Port "+str(tp_dst)+ " is now free")


    def getNewAvailablePort(self,router):
        index_start = self.port_number_start
        index_stop = self.port_number_stop
        next_port=-1
        for current_port in range(index_start,index_stop):
            if self.external_port_counter[router,current_port]==True:
                self.external_port_counter[router,current_port]=False
                next_port = current_port
                break
        self.logger.info(">>Next port: "+str(next_port))
        return next_port
