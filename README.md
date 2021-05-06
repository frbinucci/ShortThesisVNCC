# ShortThesisVNCC
This repository contains the script used in order to implement a simple example of SDN network built using Mininet and Ryu

## Instructions

### Instruction for composing the configuration file
Put the file parma.conf in ryu/app/param.conf. 
This file defines:
1)Information about NAT
2)Information about gateways
3)Information about a very simple DHCP server

Here's an example of param.conf file:

    #TOPOLOGY CONFIGURATION PARAMETERS
    [DEFAULT]
    #NAT INFORMATION
    #1)List of dpid with nat function
    #2)List of external ip (public)
    #3)List of next hops
    #4)List of external mac addresses
    #5)List of external gateway mac addresses
    #6)List of external port to send packages
    #7)List of ovs internal ports.
    nat_list=3,4
    nat_external_ip_list=1.1.1.1,2.2.2.1
    nat_external_gateway_list=1.1.1.2,2.2.2.2
    nat_external_mac_list=00:00:00:00:00:19,00:00:00:00:00:18
    nat_external_gateway_mac_list=00:00:00:00:00:20,00:00:00:00:00:21
    nat_external_port_list=6,3
    nat_internal_port_list=2,2

    #GATEWAY INFORMATION
    #Information about gateways are described by the following syntax. Different gateways are divided by a comma.
    #dpid#gateway_ip_address-physical_port_number;mac_address
    gw_dpid_list=3,4,8
    gateway_list=3#10.0.1.254-1;00:00:00:00:00:10,3#10.0.2.254-2;00:00:00:00:00:11,3#10.0.3.254-3;00:00:00:00:00:12,3#192.168.0.1-5;00:00:00:00:00:13,4#10.1.5.254-2;00:00:00:00:00:15,4#192.168.0.2-1;00:00:00:00:00:14,8#8.8.8.254-1;00:00:00:00:00:0A
    
    #DHCP INFORMATION
    #Information about dhcp are coded with the key 'dhcp_servers'. You can define your dhcp parameters with the following syntax. 
    #Information about different servers are divided by a comma.
    #dhcp_servers=datapath_id#datapath_port#gateway_hw_address#gateway_ip_address#net_id#subnet_mask#start_ip_address#pool_length,dapath_id#datapath_port...
    dhcp_servers=3#2#00:00:00:00:00:11#10.0.2.254#10.0.2.0#255.255.255.0#10.0.2.50#25,3#1#00:00:00:00:00:10#10.0.1.254#10.0.1.0#255.255.255.0#10.0.1.10#10


### Instruction to run the network

Work in progres...

