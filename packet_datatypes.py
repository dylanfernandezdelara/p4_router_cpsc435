from scapy.fields import ByteField, ShortField, FieldLenField, PacketListField, IPField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP

TYPE_CPU_METADATA = 0x080a
ALLRoutersAreaID = '224.0.0.5' # TO MODIFY?
PWOSPF_HELLO_TYPE = 1
PWOSPF_LSU_TYPE = 4
PWOSPF_PROT_NUM = 89

class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [ ByteField("fromCpu", 0),
                    ShortField("origEtherType", None),
                    ShortField("srcPort", None),
                    ShortField("dstPort", None)]

class PWOSPF(Packet):
    name = "PWOSPF"
    fields_desc = [ ByteField("version", 2),
                    ByteField("type", 1),
                    ShortField("length", None),
                    IPField("routerID", "0.0.0.0"),
                    IPField("areaID", ALLRoutersAreaID),
                    ShortField("checksum", None),
                    ShortField("auType", None),
                    ShortField("authentication", None)
                    ]

class Hello(Packet):
    name = "Hello"
    fields_desc = [ IPField("networkMask", "0.0.0.0"),
                    ShortField("helloInterval", None),
                    ShortField("padding", None)
                    ]

class LSUAd(Packet):
    name = 'Advertisement'
    fields_desc = [
        IPField('subnet', '0.0.0.0'),
        IPField('mask', '0.0.0.0'),
        IPField('routerID', '0.0.0.0')
    ]

    def remove_padding(self, ad):
        return '', ad

class LSU(Packet):
    name = "LSU"
    fields_desc = [ ShortField("seqNum", None),
                    ShortField("ttl", None),
                    FieldLenField('numAds', None, count_of='ads'),
                    PacketListField('ads', [], LSUAd,
                        count_from=lambda pkt: pkt.adcnt,
                        # length of an Advertisement packet
                        length_from=lambda pkt: pkt.adcnt * 12)

    ]

bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
bind_layers(CPUMetadata, ARP, origEtherType=0x0806)

bind_layers(IP, PWOSPF, proto=PWOSPF_PROT_NUM)
bind_layers(PWOSPF, Hello, type=PWOSPF_HELLO_TYPE)
bind_layers(PWOSPF, LSU, type=PWOSPF_LSU_TYPE)
