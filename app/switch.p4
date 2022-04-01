/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


#define CPU_PORT 255

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x0806;

const bit<16> ARP_OP_REQUEST = 1;
const bit<16> ARP_OP_RESPOND = 2;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;
typedef bit<16> McastGrp_t;


@controller_header("packet_in")
header PacketIn_t {
    bit<16> ingress_port; 
    macAddr_t srcAddr;
}

@controller_header("packet_out")
header PacketOut_t {
    bit<16> egress_port; 
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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    ipv4_t       ipv4;
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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


struct digest_t {
    macAddr_t srcAddr;
    bit<9> ingressPort;
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    bit <9> temp_port;
    bit <7> mcast;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action broadcast(McastGrp_t mgrp) {
        standard_metadata.mcast_grp = mgrp;
    }

    action mac_to_port(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }


    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    action learn_mac() {
        digest<digest_t>(0, {hdr.ethernet.srcAddr, standard_metadata.ingress_port});
    }

    table smac_table {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            learn_mac;
            NoAction;
        }
        size = 4096;
    }

    table mac_table {
        key = {
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            mac_to_port;
            send_to_cpu;
            broadcast;
        }
        size = 1024;
        default_action = send_to_cpu();
    }
    table mac_table_check {
        key = {
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            mac_to_port;
            send_to_cpu;
            broadcast;
        }
        size = 1024;
        default_action = send_to_cpu();
    }

    table mac_table_hit {
        key = {
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            mac_to_port;
            send_to_cpu;
            broadcast;
        }
        size = 1024;
        default_action = send_to_cpu();
    }

    apply {

        if(standard_metadata.ingress_port == CPU_PORT) {
            
            temp_port = (bit<9>)hdr.pktOut.egress_port[5:3];
            mcast = (bit<7>)hdr.pktOut.egress_port[0:0];
            if(mac_table_check.apply().miss) {
                if(mcast == 1) {
                    standard_metadata.mcast_grp = (bit<16>) mcast;
                    standard_metadata.ingress_port = temp_port;
                }
            }
            else {
                if(standard_metadata.mcast_grp == 1) {
                    standard_metadata.ingress_port = temp_port;    
                }
                
            }
            hdr.pktOut.setInvalid();
        }           
        else if((hdr.ethernet.etherType == TYPE_ARP) || (hdr.ethernet.etherType == 0x800)){
            if(smac_table.apply().miss) { 
                if(mac_table.apply().hit) {
                    learn_mac();
                }
                else {
                    hdr.pktIn.setValid();
                    hdr.pktIn.srcAddr = hdr.ethernet.srcAddr;    
                }
            }
            else {
                mac_table_hit.apply();
            }

            if (standard_metadata.egress_spec == CPU_PORT) { // packet in
                if(!hdr.pktIn.isValid()) {
                    hdr.pktIn.setValid();
                    hdr.pktIn.srcAddr = 0x000000000000;
                }
                hdr.pktIn.ingress_port = (bit<16>)standard_metadata.ingress_port;
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }
    apply { 
        //packet does not send back to source in broadcast action
        if(standard_metadata.egress_port == standard_metadata.ingress_port) {
            drop();
        }
     }
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
        //packet.emit(hdr.arp);
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

