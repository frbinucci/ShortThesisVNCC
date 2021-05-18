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
from ryu.lib import addrconv
from ryu.lib.packet import packet
from IPtoMac import IPtoMac

from ryu import cfg
import Constants
import ipaddress
#from __future__ import unicode_literals

class DHCP(app_manager.RyuApp):
    def __init__(self,*args,**kwargs):
        super(DHCP, self).__init__(*args, **kwargs)
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.StrOpt('dhcp_servers', default=0, help = ('dhcp_servers'))
        ])
        self.dhcp_servers = CONF.dhcp_servers.split(",")
        self.dhcp_association = {}
        self.dhcp_table = {}
        for current_server in self.dhcp_servers:
            dhcp_servers_param = current_server.split('#')
            dpid = dhcp_servers_param[0]
            port = dhcp_servers_param[1]
            server_ip = dhcp_servers_param[2]
            hw_address = dhcp_servers_param[3]
            net_id = dhcp_servers_param[4]
            netmask = dhcp_servers_param[5]
            start_address = dhcp_servers_param[6]
            number_address = dhcp_servers_param[7]
            self.dhcp_association[dpid,port] = (server_ip,hw_address,net_id,netmask,start_address)
            self.dhcp_table[dpid,port]=list()
            ip4_address = ipaddress.ip_address(start_address.decode('utf8'))
            self.dhcp_table[dpid, port] = list()
            for i in range(int(number_address)):
                self.dhcp_table[dpid,port].append(IPtoMac(ip4_address,None))
                ip4_address+=1
                i+=1



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        dhcp_data = pkt.get_protocol(dhcp.dhcp)

        if dhcp_data!=None:
            if  (str(dpid),str(msg.in_port)) in self.dhcp_association.keys():
                for opt in (dhcp_data.options.option_list):
                    if opt.tag==53:
                        if ord(opt.value)==Constants.DHCP_DISCOVER:
                            self.handle_dhcp_discover(pkt,datapath,msg.in_port)
                        elif ord(opt.value)==Constants.DHCP_REQUEST:
                            self.handle_dhcp_request(pkt,datapath,msg.in_port)
                        elif ord(opt.value)==Constants.DHCP_RELEASE:
                            self.handle_dhcp_release(pkt,datapath,msg.in_port)

    def handle_dhcp_release(self,pkt,datapath,port):
        dpid = datapath.id
        rel_ipv4 = pkt.get_protocol(ipv4.ipv4)

        i=0
        for association in self.dhcp_table[str(dpid),str(port)]:
                if association.getIp_address()==ipaddress.ip_address(str(rel_ipv4.src).decode('utf-8')):
                    self.dhcp_table[str(dpid),str(port)][i].setMac_address(None)
                    print("Address released: "+rel_ipv4.src)
                    break
                i+=1




    def handle_dhcp_request(self,pkt,datapath,port):
        dpid = datapath.id
        req_eth = pkt.get_protocol(ethernet.ethernet)
        req_ipv4 = pkt.get_protocol(ipv4.ipv4)
        req_udp = pkt.get_protocol(udp.udp)
        req = pkt.get_protocol(dhcp.dhcp)
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 53))
        req.options.option_list.insert(0, dhcp.option(tag=51, value='8640'))
        req.options.option_list.insert(
            0, dhcp.option(tag=1, value=addrconv.ipv4.text_to_bin(self.dhcp_association[str(dpid),str(port)][3])))
        req.options.option_list.insert(
            0, dhcp.option(tag=3, value=addrconv.ipv4.text_to_bin(self.dhcp_association[str(dpid),str(port)][1])))
        req.options.option_list.insert(
            0, dhcp.option(tag=53, value=Constants.DHCP_ACK_HEX))



        hw_addr = req_eth.src
        for association in self.dhcp_table[str(dpid),str(port)]:
            if association.getMac_address() == hw_addr:
                ip_addr=format(association.getIp_address())

        dhcp_packet_res = dhcp.dhcp(op=2,
                                    chaddr=hw_addr,
                                    options=req.options,
                                    xid=req.xid,
                                    ciaddr='0.0.0.0',
                                    yiaddr=ip_addr,
                                    siaddr=self.dhcp_association[str(dpid),str(port)][1],
                                    boot_file=req.boot_file)

        self.send_dhcp_packet(dhcp_packet_res,req_ipv4.proto,req_eth.src,'255.255.255.255',datapath,port)


    def handle_dhcp_discover(self,pkt,datapath,port):
        ipv4discovery = pkt.get_protocol(ipv4.ipv4)
        dpid = datapath.id
        dhcp_packet = pkt.get_protocol(dhcp.dhcp)

        hw_addr = dhcp_packet.chaddr
        ass_list = self.dhcp_table[str(dpid),str(port)]
        client_ip_address=None
        found_address=False
        for association in self.dhcp_table[str(dpid),str(port)]:
            print(str(association.getIp_address())+","+str(association.getMac_address()))
            if association.getMac_address() == None:
                found_address=True
                association.setMac_address(hw_addr)
                client_ip_address = association.getIp_address()
                break

        if found_address:
            dhcp_packet.options.option_list.remove(
                next(opt for opt in dhcp_packet.options.option_list if opt.tag == 55))
            #dhcp_packet.options.option_list.remove(
            #    next(opt for opt in dhcp_packet.options.option_list if opt.tag == 50))
            dhcp_packet.options.option_list.remove(
                next(opt for opt in dhcp_packet.options.option_list if opt.tag == 53))
            dhcp_packet.options.option_list.remove(
                next(opt for opt in dhcp_packet.options.option_list if opt.tag == 12))
            dhcp_packet.options.option_list.insert(
                0, dhcp.option(tag=1, value=addrconv.ipv4.text_to_bin(self.dhcp_association[str(dpid),str(port)][3])))
            dhcp_packet.options.option_list.insert(
                0, dhcp.option(tag=3, value=addrconv.ipv4.text_to_bin(self.dhcp_association[str(dpid),str(port)][1])))
            dhcp_packet.options.option_list.insert(
                0, dhcp.option(tag=53, value='\x02'))
            dhcp_packet.options.option_list.insert(
                0, dhcp.option(tag=54, value=addrconv.ipv4.text_to_bin(self.dhcp_association[str(dpid),str(port)][1])))
            dhcp_packet_res = dhcp.dhcp(op=2,
                                        chaddr=hw_addr,
                                        options=dhcp_packet.options,
                                        xid=dhcp_packet.xid,
                                        yiaddr=client_ip_address,
                                        siaddr=self.dhcp_association[str(dpid),str(port)][1],
                                        boot_file=dhcp_packet.boot_file)
            self.send_dhcp_packet(dhcp_packet_res,ipv4discovery.proto,hw_addr,'255.255.255.255',datapath,port)

    def send_dhcp_packet(self,dhcp_packet,protocol,hw_addr,ip_addr,datapath,port):

        dpid = datapath.id

        packet_to_send = packet.Packet()
        packet_to_send.add_protocol(ethernet.ethernet(dst=hw_addr,src=self.dhcp_association[str(dpid),str(port)][0],ethertype=ether_types.ETH_TYPE_IP))

        packet_to_send.add_protocol(ipv4.ipv4(src=self.dhcp_association[str(dpid),str(port)][1],dst=ip_addr,proto=protocol))
        packet_to_send.add_protocol(udp.udp(src_port=67,dst_port=68))
        packet_to_send.add_protocol(dhcp_packet)

        packet_to_send.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=packet_to_send.data)
        datapath.send_msg(out)

