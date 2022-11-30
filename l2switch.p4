/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT           = 0x1;

const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<16> TYPE_IPV4         = 0x0800;

// counters
counter(1, CounterType.packets) count_ip_packets;
counter(1, CounterType.packets) count_arp_packets;
counter(1, CounterType.packets) count_cpu_packets;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
    bit<16> dstPort; // couldn't find a better way to get this value from the controller, so going to pass it up
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
}

struct metadata { }

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4; // normal packets being forwarded
            TYPE_ARP: parse_arp; // receiving arp packets from other switches
            TYPE_CPU_METADATA: parse_cpu_metadata; // cpu is sending an arp packet, so it has cpu_metadata
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp; // cpu is sending an arp packet
            TYPE_IPV4: parse_ipv4; // this is a packet from the controller, so it has ipv4
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    //     verify_checksum(
    //         hdr.ipv4.isValid(),
    //         hdr.ipv4.hdrChecksum,
    //         { hdr.ipv4.version,
    //           hdr.ipv4.ihl,
    //           hdr.ipv4.diffserv,
    //           hdr.ipv4.totalLen,
    //           hdr.ipv4.identification,
    //           hdr.ipv4.flags,
    //           hdr.ipv4.fragOffset,
    //           hdr.ipv4.ttl,
    //           hdr.ipv4.protocol,
    //           hdr.ipv4.srcAddr,
    //           hdr.ipv4.dstAddr },
    //         HashAlgorithm.csum16);
}
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    macAddr_t next_mac_addr = 0;
    ip4Addr_t next_ip_addr = 0;

    /***
    *** IP LAYER 
    ***/
    action forwarding_path(ip4Addr_t next_ip, port_t p_port) {
        next_ip_addr = next_ip;
        standard_metadata.egress_port = p_port;
    }

    table controller_local_forwarding_table {
        key = {
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            forwarding_path;
            send_to_cpu;
        }
        size = 1024;
    }

    table routing_table {
        key = {
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            forwarding_path;
            send_to_cpu;
        }
        size = 1024;
        default_action = send_to_cpu();
    }

    /***
    *** ETH LAYER 
    ***/
    action match_arp_addr(macAddr_t next_mac){
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = next_mac;
    }

    table arp_table {
        key = {
            next_ip_addr: exact;
        }
        actions = {
            match_arp_addr;
            NoAction;
        }
        default_action = NoAction;
        size = 64;
    }

    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (standard_metadata.ingress_port == CPU_PORT)
            cpu_meta_decap();

        if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            count_arp_packets.count(0); // might need to cast to bit<32>
            send_to_cpu();
        }
        // ARP logic will be handled in the control plane
        else if (standard_metadata.ingress_port == CPU_PORT && hdr.cpu_metadata.dstPort != 0){
            standard_metadata.egress_spec = (bit<9>)hdr.cpu_metadata.dstPort;
        }
        else if (hdr.ipv4.isValid()) {
            count_ip_packets.count(0); // might need to cast to bit<32>

            hdr.ipv4.ttl = hdr.ipv4.ttl - 1; // decrement ttl
            if (hdr.ipv4.ttl <= 0) {
                drop();
            }

            if (!controller_local_forwarding_table.apply().hit)
            {
                routing_table.apply();
                arp_table.apply();
            }
        }
        else if (hdr.ethernet.isValid()) {
            fwd_l2.apply();
        }
        else {
            send_to_cpu();
        }

        if(standard_metadata.egress_spec == CPU_PORT)
        {
            count_cpu_packets.count(0);
        }

    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;