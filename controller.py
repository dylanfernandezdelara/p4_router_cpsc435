from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP
from async_sniff import sniff
from packet_datatypes import CPUMetadata, Hello, LSU, LSUAd, PWOSPF
import time
import collections

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
ALLRoutersAreaID = '224.0.0.5'
LSU_INT = 5
PWOSPF_PROT_NUM = 89
PWOSPF_HELLO_TYPE = 1
PWOSPF_LSU_TYPE = 4
start_wait=0.3

class MacLearningController(Thread):
    def __init__(self, sw, macAddr, routerID, hello_int, lsu_int):
        super(MacLearningController, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.stop_event = Event()
        self.mac_for_ip = {}
        self.mac_for_ip_times = {}
        self.macAddr = macAddr

        self.adj_list = []
        self.adj_list_timeout = []
        self.last_packets = []

        self.routerID = routerID
        self.areaID = ALLRoutersAreaID
        self.helloint = hello_int
        self.lsuint = lsu_int
        self.seq_num_lsu = 0

        self.sending_hello_thread = Periodic_Hello_Sender(routing_controller=self)
        self.sending_lsu_thread = Periodic_LSU_Sender(routing_controller=self)

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port
    
    def addIPAddr(self, ip, mac):
        # Don't re-add the ip-mac mapping if we already have it:
        if ip in self.mac_for_ip: return

        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
            match_fields={'next_ip_addr': [ip]},
            action_name='MyIngress.match_arp_addr',
            action_params={'next_mac': mac})
        self.mac_for_ip[ip] = mac
        # self.mac_for_ip_times[ip] = time.time()

    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        # print("ARP reply from %s" % pkt[ARP].psrc)
        # print("hwsrc: %s" % pkt[ARP].hwsrc)

        self.addIPAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.send(pkt)
    
    def generate_arp_reply(self, pkt):
        if pkt[ARP].pdst == (self.routerID + '0'):
            ip_dest = pkt[ARP].pdst
            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = self.macAddr
            pkt[ARP].op = ARP_OP_REPLY
            pkt[ARP].pdst = pkt[ARP].psrc
            pkt[ARP].psrc = ip_dest
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            pkt[ARP].hwsrc = self.macAddr
        return pkt
        

    def handleArpRequest(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        # print("ARP request from %s" % pkt[ARP].psrc)
        # print("hwsrc: %s" % pkt[ARP].hwsrc)
        
        self.addIPAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)

        pkt = self.generate_arp_reply(pkt)

        self.send(pkt)

    def floodLSUPkt(self, pkt):
        newTTL = pkt[LSU].ttl - 1
        if newTTL > 0:
            for n in self.adj_list[self.routerID][0]:
                    newPkt = pkt
                    key_mac = self.mac_for_ip[n]
                    key_port = self.port_for_mac[key_mac]
                    newPkt[CPUMetadata].dstPort = key_port
                    newPkt[IP].dst = n
                    newPkt[LSU].ttl = newTTL
                    if newPkt[IP].dst != newPkt[IP].src:
                        self.send(newPkt)

    def generate_router_datatype(self, routerID):
        return (routerID, ALLRoutersAreaID, LSU_INT)

    def compute_shortest_path(self):
        visited = set()
        visited.add(self.routerID)
        path = {}
        queue = collections.deque([])
        for routerId in self.adj_list[self.routerID][0]:
            path[routerId] = routerId
            visited.add(routerId)
            queue.append(routerId)
        
        while(queue):
            curr_routerID = queue.popleft()
            curr_best_path = path[curr_routerID]
            for neighbor_routerID in self.adj_list[curr_routerID][0]:
                if(neighbor_routerID not in visited):
                    visited.add(neighbor_routerID)
                    path[neighbor_routerID] = curr_best_path
                    queue.append(neighbor_routerID)
        return path
    
    def update_table(self, path):
        for key in path.keys():
            print("key: %s\n" % key)
            key_mac = self.mac_for_ip[path[key]]
            key_port = self.port_for_mac[key_mac]

            self.sw.insertTableEntry(table_name = 'MyIngress.routing_table',
            match_fields = {'hdr.ipv4.dstAddr': path[key]},
            action_name = 'MyIngress.forwarding_path',
            action_params = {'next': path[key], 'port': key_port})

    def handlePkt(self, pkt):
        #pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
        
        if ICMP in pkt:
            # to do handle ICMP packet
            return
        
        if IP in pkt:
            # to do handle IP packet
            # if pkt dest not in intfs and dest is not for hello then icmp unreachable
            return 

        if PWOSPF in pkt:
            if pkt[PWOSPF].version != 2:
                return
            
            routerID = pkt[IP].src
            if pkt[PWOSPF].type == 1 and Hello in pkt:
                # if router has neighbor already, update timeout
                if routerID not in self.adj_list:
                    # else add neighbor to list
                    new_router = self.generate_router_datatype(routerID)
                    curr_router = self.generate_router_datatype(self.routerID)
                    self.adj_list[routerID].append(curr_router)
                    self.adj_list[self.routerID].append(new_router)

                self.adj_list_timeout[routerID] = time.time()
            
            if pkt[PWOSPF].type == 4 and LSU in pkt:
                # If the LSU was originally generated by the incoming router, the packet is dropped
                if self.routerID == routerID:
                    return

                if routerID in self.last_packets:
                    last_pkt_received = self.last_packets[routerID]
                    if last_pkt_received[LSU].seq == pkt[LSU].seq:
                        return
                
                self.last_packets[routerID] = pkt

                # update database
                for LSUAd in pkt[LSU].ads:
                    ad_routerID = LSUAd.routerID
                    if ad_routerID not in self.adj_list:
                        self.adj_list[ad_routerID] = []
                    
                    ad_router_datatype = self.generate_router_datatype(ad_routerID)
                    curr_router_datatype = self.generate_router_datatype(self.routerID)

                    if ad_router_datatype not in self.adj_list[routerID]:
                        self.adj_list[routerID].append(self.generate_router_datatype(ad_routerID))
                    if curr_router_datatype not in self.adj_list[ad_routerID]:
                        self.adj_list[ad_routerID].append(self.generate_router_datatype(routerID))
                
                # recompute shortest paths
                shortest_paths = self.compute_shortest_paths()
                self.update_table(shortest_paths)
                
                # flood packets
                self.floodLSUPkt(pkt)

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(MacLearningController, self).start(*args, **kwargs)

        # add monolith ARP, LSU, Hello Packet Managers
        # call .start()
        # self.sending_hello_thread.start()
        # self.sending_lsu_thread.start()

        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(MacLearningController, self).join(*args, **kwargs)

class Periodic_Hello_Sender(Thread):
    def __init__(self, routing_controller):
        super(Periodic_Hello_Sender, self).__init__()
        self.sender_ctrl = routing_controller

    def run(self):
        for i in range(5): # for each port 
            if i != 4:
                port = i
                pkt = Ether()/CPUMetadata()/IP()/PWOSPF()/Hello()
                pkt[Ether].src = self.sender_ctrl.macAddr
                pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
                pkt[CPUMetadata].fromCpu = 1
                pkt[CPUMetadata].origEtherType = 0x0800
                pkt[CPUMetadata].srcPort = 1
                pkt[CPUMetadata].dstPort = port
                pkt[IP].src = self.sender_ctrl.routerID
                pkt[IP].dst = "224.0.0.5"
                pkt[IP].proto = PWOSPF_PROT_NUM
                pkt[PWOSPF].version = 2
                pkt[PWOSPF].type = PWOSPF_HELLO_TYPE
                pkt[PWOSPF].length = 0
                pkt[PWOSPF].routerID = self.sender_ctrl.routerID
                pkt[PWOSPF].areaID = self.sender_ctrl.areaID
                pkt[PWOSPF].checksum = 0
                pkt[Hello].netmask = 0
                pkt[Hello].helloint = self.sender_ctrl.helloint

                self.sender_ctrl.send(pkt)

        time.sleep(self.sender_ctrl.helloint)

class Periodic_LSU_Sender(Thread):
    def __init__(self, routing_controller):
        super(Periodic_LSU_Sender, self).__init__()
        self.sending_ctrl = routing_controller

    def run(self):
            adList = []
            for n in self.sending_ctrl.adj_list:
                    pkt = LSUAd()
                    pkt[LSUAd].subnet = 0
                    pkt[LSUAd].mask = 0
                    pkt[LSUAd].routerID = n[0]
                    adList.append(pkt)

            # Send LSU packet
            pkt = Ether()/CPUMetadata()/IP()/PWOSPF()/LSU()
            pkt[Ether].src = self.sending_ctrl.macAddr
            pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
            pkt[CPUMetadata].fromCpu = 1
            pkt[CPUMetadata].origEtherType = 0x0800
            pkt[CPUMetadata].srcPort = 1
            pkt[IP].src = self.sending_ctrl.routerID
            pkt[IP].proto = PWOSPF_PROT_NUM
            pkt[PWOSPF].version = 2
            pkt[PWOSPF].type = PWOSPF_LSU_TYPE
            pkt[PWOSPF].length = 0
            pkt[PWOSPF].routerID = self.sending_ctrl.routerID
            pkt[PWOSPF].areaID = self.sending_ctrl.areaID
            pkt[PWOSPF].checksum = 0
            pkt[LSU].sequence = self.sending_ctrl.seq_num_lsu
            pkt[LSU].ttl = 64
            pkt[LSU].numAds = len(adList)
            pkt[LSU].adList = adList

            self.sending_ctrl.seq_num_lsu = self.sending_ctrl.seq_num_lsu + 1
            self.sending_ctrl.floodLSUPkt(pkt)

            time.sleep(self.sending_ctrl.lsuint)
