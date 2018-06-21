
class layer():
    def classification(self):
        return self.highest_layer

class ethernet():
    def src_mac(self):
        return (self.eth.src)

    def dst_mac(self):
        return (self.eth.dst)

class ip_layer():
    def src_ip(self):
        return self.ip.src
    def dst_ip(self):
        return self.ip.dst