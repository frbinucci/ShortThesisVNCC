from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.util import irange

class BusinessNetwork(Topo):
    def build(self,numHostPerSwitch,dhcp):
        
        NETWORK_1_PREFIX = '10.0.1'
        NETWORK_2_PREFIX = '10.0.2'
        NETWORK_3_PREFIX  = '10.1.5'
        NETWORK_4_PREFIX  = '10.2.5'

        self.network_prefixes = [NETWORK_1_PREFIX,NETWORK_2_PREFIX,NETWORK_3_PREFIX,NETWORK_4_PREFIX]


        
        #Creating switches
        s1 = self.addSwitch('s1',dpid = '1')
        s2 = self.addSwitch('s2',dpid = '2')
        s3 = self.addSwitch('s3',dpid = '5')

        #Creating routers
        r1 = self.addSwitch('r1',dpid = '3')
        r2 = self.addSwitch('r2',dpid = '4')
        r3 = self.addSwitch('r3',dpid= '8')

        switches =[s1,s2,s3]

        #dhcp = bool(dhcp)

        for i in range(0,len(switches)):
            for j in irange(1,numHostPerSwitch):
                if dhcp=='True':
                    host = self.addHost('h' + str(j) + 's' + str(i + 1),ip='no ip defined')
                else:
                    host = self.addHost('h'+str(j)+'s'+str(i+1),ip=self.network_prefixes[i]+'.'+str(j)+'/24',defaultRoute='via '+ self.network_prefixes[i]+".254")
                self.addLink(switches[i],host)


        internalServerWeb = self.addHost('isw',ip='10.0.3.1/24',defaultRoute='via 10.0.3.254')
        externalServerWeb = self.addHost('esx',ip='10.0.4.1/24',defaultRoute='via 10.0.4.254')

        internetServerWeb = self.addHost('google',ip='8.8.8.8/24',defaultRoute='via 8.8.8.254')

        self.addLink(r1,s1)
        self.addLink(r1,s2)
        self.addLink(internalServerWeb,r1)
        self.addLink(externalServerWeb,r1)
        self.addLink(r2,r1)
        self.addLink(r2,s3)

        self.addLink(r3,internetServerWeb)
        self.addLink(r1,r3)
        self.addLink(r2,r3)


# Allows the file to be imported using `mn --custom <filename> --topo minimal`
topos = {
    'configurableNetwork': BusinessNetwork
}



