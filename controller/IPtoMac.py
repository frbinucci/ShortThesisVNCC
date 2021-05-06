class IPtoMac():
    def __init__(self,ip_address,mac_address):
        self.ip_address = ip_address
        self.mac_address=mac_address

    def getIp_address(self):
        return self.ip_address

    def getMac_address(self):
        return self.mac_address

    def setMac_address(self,mac):
        self.mac_address = mac