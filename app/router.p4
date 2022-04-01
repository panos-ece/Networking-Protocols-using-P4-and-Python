/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


#define CPU_PORT 255

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;
const bit<8> TYPE_UDP = 17;

const bit<16> ARP_OP_REQUEST = 1;
const bit<16> ARP_OP_RESPOND = 2;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;


@controller_header("packet_in")
header PacketIn_t {
    bit<16> ingress_port; /* suggested port where the packet should be sent */
}

@controller_header("packet_out")
header PacketOut_t {
    bit<16> egress_port; /* suggested port where the packet should be sent */
}


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    bit<48> sha;
    bit<32> spa;
    bit<48> tha;
    bit<32> tpa;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    ipv4_t       ipv4;
    udp_t        udp;
    PacketIn_t   pktIn;
    PacketOut_t  pktOut;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packetOut;
            default: parse_ethernet;
            }
    }

    state parse_packetOut {
        packet.extract(hdr.pktOut);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
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
        /*transition select(hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp;
            default: accept;
        }*/
    }

    /*state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }*/
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    /*action mac_to_port(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }*/

    action arp_respond(macAddr_t dstAddr) {
        hdr.ethernet.srcAddr = dstAddr;
        hdr.ethernet.dstAddr = hdr.arp.sha;

        hdr.arp.htype = 1;
        hdr.arp.ptype = TYPE_IPV4;
        hdr.arp.hlen = 6;
        hdr.arp.plen = 4;
        hdr.arp.oper = 2;
        hdr.arp.tha = hdr.arp.sha;

        ipv4Addr_t tempTPA = hdr.arp.tpa;

        hdr.arp.tpa = hdr.arp.spa;
        hdr.arp.sha = dstAddr;
        hdr.arp.spa = tempTPA;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }


    table arp_table {
        key = {
            hdr.arp.tpa: exact;
        }
        actions = {
            arp_respond;
            send_to_cpu;
            drop;
        }
        size = 1024;
        default_action = send_to_cpu();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /*action nat_encap(macAddr_t srcAddr, macAddr_t dstAddr,ipv4Addr_t srcIP, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = srcAddr;
        //hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ipv4.srcAddr = srcIP;
    }
    action nat_decap(macAddr_t srcAddr, macAddr_t dstAddr,ipv4Addr_t dstIP, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        //hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ipv4.dstAddr = dstIP;
    }*/
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
            //hdr.ipv4.protocol: exact;
        }
        actions = {
            ipv4_forward;
            send_to_cpu;
            //nat_encap;
            //nat_decap;
        }
        size = 1024;
        default_action = send_to_cpu();
    }
    
    apply {

        if(standard_metadata.ingress_port == CPU_PORT) {
            standard_metadata.egress_spec = (bit<9> ) hdr.pktOut.egress_port;
            hdr.pktOut.setInvalid();
        }
        else if((hdr.ethernet.etherType == TYPE_ARP) && (hdr.arp.oper == ARP_OP_REQUEST)) {
            arp_table.apply();
        }
        else if(hdr.ethernet.etherType == TYPE_IPV4) {
            ipv4_lpm.apply();
        }

        if (standard_metadata.egress_spec == CPU_PORT) { // packet in
            hdr.pktIn.setValid();
            hdr.pktIn.ingress_port = (bit<16>)standard_metadata.ingress_port;
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.pktIn);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

