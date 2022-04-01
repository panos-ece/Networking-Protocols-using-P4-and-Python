#!/usr/bin/env python3
import argparse
from asyncio import ReadTransport
from hmac import digest
import grpc
import os
import sys
from time import sleep
from time import time_ns
from threading import Lock
from threading import Thread
from threading import current_thread
from threading import get_ident
from threading import get_native_id

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper
import p4runtime_lib.convert as convert

mac_to_port = {}
lock = Lock()

def write_IPv4_Rules(p4info_helper,ingress_sw,ipv4_dst,lpm,dst_mac,out_port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (ipv4_dst,lpm)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_mac,
            "port": out_port
        })
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed ipv4 rule on %s" % ingress_sw.name)

def write_Arp_Rules(p4info_helper, ingress_sw, arp_tpa, arp_tha):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.arp_table",
        match_fields={
            "hdr.arp.tpa": arp_tpa
        },
        action_name="MyIngress.arp_respond",
        action_params={
            "dstAddr": arp_tha
        })
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed arp rule on %s" % ingress_sw.name)

def write_Arp__Drop_Rules(p4info_helper, ingress_sw, arp_tpa):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.arp_table",
        match_fields={
            "hdr.arp.tpa": arp_tpa
        },
        action_name="MyIngress.drop")
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed arp drop rule on %s" % ingress_sw.name)


def write_mac_table_check_rules(p4info_helper, ingress_sw, dst_eth_addr, port):
    if(port != -1):
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.mac_table_check",
            match_fields={
                "hdr.ethernet.dstAddr": dst_eth_addr
            },
            action_name="MyIngress.mac_to_port",
            action_params={
                "port": port
            })
        ingress_sw.WriteTableEntry(table_entry)
        print("Installed mac_table_check rule on %s" % ingress_sw.name)
    else:
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.mac_table_check",
            match_fields={
                "hdr.ethernet.dstAddr": dst_eth_addr
            },
            action_name="MyIngress.broadcast",
            action_params={
                "mgrp": 1
            })
        ingress_sw.WriteTableEntry(table_entry)
        print("Installed broadcast mac_table_check rule on %s" % ingress_sw.name)


def write_mac_table_rules(p4info_helper, ingress_sw, dst_eth_addr, port):
    if(port != -1):
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.mac_table",
            match_fields={
                "hdr.ethernet.dstAddr": dst_eth_addr
            },
            action_name="MyIngress.mac_to_port",
            action_params={
                "port": port
            })
        ingress_sw.WriteTableEntry(table_entry)
        print("Installed mac_table rule on %s" % ingress_sw.name)
    else:
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.mac_table",
            match_fields={
                "hdr.ethernet.dstAddr": dst_eth_addr
            },
            action_name="MyIngress.broadcast",
            action_params={
                "mgrp": 1
            })
        ingress_sw.WriteTableEntry(table_entry)
        print("Installed broadcast mac_table rule on %s" % ingress_sw.name)

def write_mac_table_hit_rules(p4info_helper, ingress_sw, dst_eth_addr, port):
    if(port != -1):
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.mac_table_hit",
            match_fields={
                "hdr.ethernet.dstAddr": dst_eth_addr
            },
            action_name="MyIngress.mac_to_port",
            action_params={
                "port": port
            })
        ingress_sw.WriteTableEntry(table_entry)
        print("Installed mac_table_hit rule on %s" % ingress_sw.name)
    else:
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.mac_table_hit",
            match_fields={
                "hdr.ethernet.dstAddr": dst_eth_addr
            },
            action_name="MyIngress.broadcast",
            action_params={
                "mgrp": 1
            })
        ingress_sw.WriteTableEntry(table_entry)
        print("Installed broadcast mac_table_hit rule on %s" % ingress_sw.name)

def write_smac_table_rules(p4info_helper, ingress_sw, src_eth_addr):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.smac_table",
        match_fields={
            "hdr.ethernet.srcAddr": src_eth_addr
        },
        action_name="NoAction")
    
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed smac_table rule on %s" % ingress_sw.name)

def extract_mac(encoded_mac,val=0):
    val = val = val.to_bytes(6,'big')
    mac = int.from_bytes(encoded_mac,byteorder='big') | int.from_bytes(val,byteorder='big')
    mac = mac.to_bytes(6,'big')
    mac = convert.decodeMac(mac)

    return(mac)

def extract_port(encoded_port):
    port = convert.decodeNum(encoded_port)

    return(port)

def mac_to_port_generate(ingress_sw):
    lock.acquire()
    mac_to_port.setdefault(ingress_sw.name, {})
    lock.release()

def mac_to_port_assign(ingress_sw,mac,port):
    lock.acquire()
    mac_to_port[ingress_sw.name][mac] = port
    lock.release()

def process_digest(p4info_helper,digest,ingress_sw):
    mac_to_port_generate(ingress_sw)
    
    print(digest)
    
    digest_id = digest.digest_id
    digest_list = digest.list_id
    
    print(digest.data[0].struct.members)

    mac = extract_mac(digest.data[0].struct.members[0].bitstring)
    port = extract_port(digest.data[0].struct.members[1].bitstring)
    
    
    print(mac)
    
    print(port)
    

    mac_to_port_assign(ingress_sw,mac,port)

    write_smac_table_rules(p4info_helper,ingress_sw,mac)
    write_mac_table_rules(p4info_helper,ingress_sw,mac,port)
    write_mac_table_hit_rules(p4info_helper,ingress_sw,mac,port)
    write_mac_table_check_rules(p4info_helper,ingress_sw,mac,port)

    print(ingress_sw.AckDigestList(digest_id,digest_list))

def arp_reply(p4info_helper,payload,ingress_sw):
    

    src_mac = payload[6:12] 
    etherType = payload[12:14]

    packet = []

    arp = payload[14:]
    opcode = arp[6:8]
    arp_req = 1
    
    if opcode == arp_req.to_bytes(2,'big'):
        tpa = arp[24:]
        
        tpa_ipv4 = convert.decodeIPv4(tpa)
        if tpa_ipv4 == "10.0.1.1":

            tpa_rule = tpa_ipv4
            opcode = convert.encodeNum(2,16)
            sha = convert.encodeMac("00:00:00:00:01:01")
            spa = convert.encodeIPv4(tpa_ipv4)
            tha = arp[8:14]
            tpa = arp[14:18]
            
            packet.extend([src_mac,sha,etherType,arp[:6],opcode,sha,spa,tha,tpa])
        elif tpa_ipv4 == "10.0.2.1":
            tpa_rule = tpa_ipv4
            opcode = convert.encodeNum(2,16)
            sha = convert.encodeMac("00:00:00:00:02:01")
            spa = convert.encodeIPv4(tpa_ipv4)
            tha = arp[8:14]
            tpa = arp[14:18]
            
            packet.extend([src_mac,sha,etherType,arp[:6],opcode,sha,spa,tha,tpa])
        else:
            tpa_rule = tpa_ipv4
            write_Arp__Drop_Rules(p4info_helper,ingress_sw,tpa_rule)
            return(None)
        
    packet_array = bytearray()
    for i in packet:
        packet_array += i

    payload = bytes(packet_array)
    print(payload)
    
    tha = convert.decodeMac(sha)
    
    print(tha)
    write_Arp_Rules(p4info_helper,ingress_sw,tpa_rule,tha)
    return(payload)

def ipv4_forwarding(p4info_helper,packet,ingress_sw,metadata):
    
    build_packet = []

    ip_dest = convert.decodeIPv4(packet[30:34])
    print("ip")
    print(ip_dest)
    
    if("10.0.1" in ip_dest):
        print("dest = 1")
        if(ingress_sw.name == 's3'):
            if(ip_dest == "10.0.1.2"):
                src_mac = convert.encodeMac("00:00:00:00:01:01")
                dst_mac = "00:00:00:00:01:02"
                

                write_IPv4_Rules(p4info_helper,ingress_sw,ip_dest,32,dst_mac,2)
                dst_mac = convert.encodeMac(dst_mac)

                build_packet.extend([dst_mac,src_mac,packet[12:]])


                packet_array = bytearray()
                for packet_fields in build_packet:
                    packet_array += packet_fields

                payload = bytes(packet_array)
                print(payload)

                metadata[0].value = convert.encodeNum(2,16)
                packet_out = p4info_helper.buildPacketOutEntry(payload,metadata)
                print(ingress_sw.PacketOut(packet_out))
            elif (ip_dest == "10.0.1.3"):
                src_mac = convert.encodeMac("00:00:00:00:01:01")
                dst_mac = "00:00:00:00:01:03"
                


                write_IPv4_Rules(p4info_helper,ingress_sw,ip_dest,32,dst_mac,2)
                dst_mac = convert.encodeMac(dst_mac)

                build_packet.extend([dst_mac,src_mac,packet[12:]])


                packet_array = bytearray()
                for packet_fields in build_packet:
                    packet_array += packet_fields

                payload = bytes(packet_array)
                print(payload)
                metadata[0].value = convert.encodeNum(2,16)
                packet_out = p4info_helper.buildPacketOutEntry(payload,metadata)
                print(ingress_sw.PacketOut(packet_out))

            print(ingress_sw.name)
        elif (ingress_sw.name == 's4'):
            src_mac = convert.encodeMac("00:00:00:00:02:01")
            dst_mac = "00:00:00:00:01:01"

            write_IPv4_Rules(p4info_helper,ingress_sw,"10.0.1.0",24,dst_mac,1)
            dst_mac = convert.encodeMac(dst_mac)

            build_packet.extend([dst_mac,src_mac,packet[12:]])


            packet_array = bytearray()
            for packet_fields in build_packet:
                packet_array += packet_fields

            payload = bytes(packet_array)
            print(payload)
            metadata[0].value = convert.encodeNum(1,16)
            packet_out = p4info_helper.buildPacketOutEntry(payload,metadata)
            print(ingress_sw.PacketOut(packet_out))

    elif "10.0.2" in ip_dest:
        print("dest = 2")
        print(ingress_sw.name)
        if(ingress_sw.name == 's3'):
            
            print(ingress_sw.name)
            src_mac = convert.encodeMac("00:00:00:00:01:01")
            dst_mac = "00:00:00:00:02:01"
            
            write_IPv4_Rules(p4info_helper,ingress_sw,"10.0.2.0",24,dst_mac,1)
            
            dst_mac = convert.encodeMac(dst_mac)

            build_packet.extend([dst_mac,src_mac,packet[12:]])


            packet_array = bytearray()
            for packet_fields in build_packet:
                packet_array += packet_fields

            payload = bytes(packet_array)
            print("I am on s3")
            print(payload)

            metadata[0].value = convert.encodeNum(1,16)
            packet_out = p4info_helper.buildPacketOutEntry(payload,metadata)
            print(ingress_sw.PacketOut(packet_out))
        elif (ingress_sw.name == 's4'):
            if(ip_dest == "10.0.2.2"):
                src_mac = convert.encodeMac("00:00:00:00:02:01")
                dst_mac = "00:00:00:00:02:02"

                write_IPv4_Rules(p4info_helper,ingress_sw,ip_dest,32,dst_mac,2)
                dst_mac = convert.encodeMac(dst_mac)

                build_packet.extend([dst_mac,src_mac,packet[12:]])


                packet_array = bytearray()
                for packet_fields in build_packet:
                    packet_array += packet_fields

                payload = bytes(packet_array)
                print(payload)

                metadata[0].value = convert.encodeNum(2,16)
                packet_out = p4info_helper.buildPacketOutEntry(payload,metadata)
                print(ingress_sw.PacketOut(packet_out))
            elif (ip_dest == "10.0.2.3"):
                src_mac = convert.encodeMac("00:00:00:00:02:01")
                dst_mac = "00:00:00:00:02:03"


                write_IPv4_Rules(p4info_helper,ingress_sw,ip_dest,32,dst_mac,2)
                dst_mac = convert.encodeMac(dst_mac)

                build_packet.extend([dst_mac,src_mac,packet[12:]])


                packet_array = bytearray()
                for packet_fields in build_packet:
                    packet_array += packet_fields

                payload = bytes(packet_array)
                print(payload)

                metadata[0].value = convert.encodeNum(2,16)
                packet_out = p4info_helper.buildPacketOutEntry(payload,metadata)
                print(ingress_sw.PacketOut(packet_out))


        print(ingress_sw.name)



def packet_router_processing(p4info_helper,ingress_sw):
    print("thread %d" % (get_native_id()))
    while True:
        print("arp_packet_in before %s" % ingress_sw.name)
        packetIn = ingress_sw.PacketIn()
        print(packetIn)
        print("arp_packet_in after %s" % ingress_sw.name)

        print("payload_arp before %s" % ingress_sw.name)
        extract_header = packetIn.packet.payload
        converted_mac = convert.decodeMac(extract_header[12:14])
        print("payload_arp after %s" % ingress_sw.name)

        print("ethertype_arp before %s" % ingress_sw.name)
        etherType = hex(int(converted_mac[0:2] + converted_mac[3:5],16))
        print("ethertype_arp after %s" % ingress_sw.name)

        if etherType == "0x806":
            print("arp_reply before %s" % ingress_sw.name)
            payload = arp_reply(p4info_helper,extract_header,ingress_sw)
            if(payload != None):
                print("arp_reply after %s" % ingress_sw.name)
                packet_out = p4info_helper.buildPacketOutEntry(payload,packetIn.packet.metadata)

                print(ingress_sw.PacketOut(packet_out))
        elif etherType == "0x800":
            ipv4_forwarding(p4info_helper,extract_header,ingress_sw,packetIn.packet.metadata)

def packet_switch_processing(p4info_helper,ingress_sw,packetIn):
    print(packetIn)
    
    if ingress_sw.name not in mac_to_port:
        print("THIS IS THE MESSAGE")
        lock.acquire()
        mac_to_port.setdefault(ingress_sw.name, {})
        lock.release()
    
    extract_header = packetIn.packet.payload
    
    dst_mac = convert.decodeMac(extract_header[0:6])
    
    print(dst_mac)

    
    lock.acquire()
    print(mac_to_port)
    if dst_mac in mac_to_port[ingress_sw.name]:
        out_port = mac_to_port[ingress_sw.name][dst_mac]
        packetIn.packet.metadata[0].value = convert.encodeNum(out_port,16)
    else:
        if(dst_mac == "ff:ff:ff:ff:ff:ff"):
            port = -1
            write_mac_table_rules(p4info_helper,ingress_sw,dst_mac,port)
            write_mac_table_hit_rules(p4info_helper,ingress_sw,dst_mac,port)
            write_mac_table_check_rules(p4info_helper,ingress_sw,dst_mac,port)
        

        
        io_num = convert.decodeNum(packetIn.packet.metadata[0].value)
        
        io_num =  '{0:01o}'.format(io_num)
        
        multi_num = '{0:01o}'.format(1)
        

        out_port = io_num + multi_num
        
        print(int(out_port))
        
        packetIn.packet.metadata[0].value = convert.encodeNum(int(out_port),16)
    lock.release()
        
        

    packet_out = p4info_helper.buildPacketOutEntry(packetIn.packet.payload,[packetIn.packet.metadata[0]])

    print(ingress_sw.PacketOut(packet_out))

def l2_function(p4info_helper,ingress_sw):
    print("thread %d" % (get_native_id()))
    print("l2_function %s" % ingress_sw.name)
    while True:
        #readTableRules(p4info_helper,ingress_sw)
        response = ingress_sw.HandleStreamMessageResponse()

        if response.HasField("digest"):
            digest_message = response
            print("Digest_message for %s" % ingress_sw.name)

            print("process_digest before %s" % ingress_sw.name)
            process_digest(p4info_helper,digest_message.digest,ingress_sw)
            print("process_digest after %s" % ingress_sw.name)
        elif ingress_sw.HandleStreamMessageResponse().HasField("packet"):
            print("packet_in before %s" % ingress_sw.name)
            packetIn = response
            print("packet_in after %s" % ingress_sw.name)
            
            if packetIn is not None:
                mac = extract_mac(packetIn.packet.metadata[1].value)
                print("HERE IS %s" % (mac))
                if(mac != "00:00:00:00:00:00"):
                    mac_to_port_generate(ingress_sw)

                    port = extract_port(packetIn.packet.metadata[0].value)

                    mac_to_port_assign(ingress_sw,mac,port)

                    write_smac_table_rules(p4info_helper,ingress_sw,mac)
                    write_mac_table_rules(p4info_helper,ingress_sw,mac,port)
                    write_mac_table_hit_rules(p4info_helper,ingress_sw,mac,port)
                    write_mac_table_check_rules(p4info_helper,ingress_sw,mac,port)

                print("processing before %s" % ingress_sw.name)
                packet_switch_processing(p4info_helper,ingress_sw,packetIn)
                print("processing after %s" % ingress_sw.name)

def initialize(p4info_helper,ingress_sw):
    replicas = [
            {
            "egress_port": 1,
            "instance": 3},
            {
            "egress_port": 2,
            "instance": 1},
            {
            "egress_port": 3,
            "instance": 2}]

    mcast = p4info_helper.buildMulticastGroupEntry(1, replicas)
    print (mcast)
    ingress_sw[0].WritePREEntry(mcast)
    ingress_sw[1].WritePREEntry(mcast)

    digest_id = p4info_helper.get_id("digests","digest_t")
    print(digest_id)
    
    digestEntry = p4info_helper.buildDigestEntry(digest_id,time_ns())
    print(digestEntry)
    
    ingress_sw[0].WriteDigestEntry(digestEntry)
    ingress_sw[1].WriteDigestEntry(digestEntry)

def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print ('%s: ' % table_name)
            for m in entry.match:
                print (p4info_helper.get_match_field_name(table_name, m.field_id))
                print ('%r' % (p4info_helper.get_match_field_value(m),))
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print ('->', action_name)
            for p in action.params:
                print (p4info_helper.get_action_param_name(action_name, p.param_id)),
                print ('%r' % p.value)
            print()
            print(entry)
            print('-----')

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper_router = p4runtime_lib.helper.P4InfoHelper(p4info_file_path[0])
    p4info_helper_switch = p4runtime_lib.helper.P4InfoHelper(p4info_file_path[1])
    
    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')
        s4 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s4',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/s4-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        s4.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper_switch.p4info,
                                       bmv2_json_file_path=bmv2_file_path[1])
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper_switch.p4info,
                                       bmv2_json_file_path=bmv2_file_path[1])
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")
        s3.SetForwardingPipelineConfig(p4info=p4info_helper_router.p4info,
                                       bmv2_json_file_path=bmv2_file_path[0])
        print("Installed P4 Program using SetForwardingPipelineConfig on s3")
        s4.SetForwardingPipelineConfig(p4info=p4info_helper_router.p4info,
                                       bmv2_json_file_path=bmv2_file_path[0])
        print("Installed P4 Program using SetForwardingPipelineConfig on s4")
        
        
        initialize(p4info_helper_switch,[s1,s2])

        s1_thread = Thread(target=l2_function, args=(p4info_helper_switch,s1))
        s2_thread = Thread(target=l2_function, args=(p4info_helper_switch,s2))
        s3_thread = Thread(target=packet_router_processing, args=(p4info_helper_router,s3))
        s4_thread = Thread(target=packet_router_processing, args=(p4info_helper_router,s4))
        

        s1_thread.start()
        s2_thread.start()
        s3_thread.start()
        s4_thread.start()
        
        print("thread %d" % (get_ident()))

        print('\n----- Reading P4INFO -----')
        
        sleep(1)
        print("I am here")

        s1_thread.join()
        print("I have gone here")
        s2_thread.join()
        s3_thread.join()
        s4_thread.join()

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', nargs=2, help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default=['./build/router.p4.p4info.txt','./build/switch.p4.p4info.txt'])
    parser.add_argument('--bmv2-json', nargs=2, help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default=['./build/router.json','./build/switch.json'])
    args = parser.parse_args()
    for i in range(len(args.p4info)):
        if not os.path.exists(args.p4info[i]):
            parser.print_help()
            print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
            parser.exit(1)
        if not os.path.exists(args.bmv2_json[i]):
            parser.print_help()
            print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
            parser.exit(1)
    main(args.p4info, args.bmv2_json)

