#!/usr/bin/env python
#coding=utf-8
from scapy.all import *
import pymongo
from threading import *

client = pymongo.MongoClient('127.0.0.1', 27017)
sniffer = client['sniffer']
packets = sniffer['packets']

#由用户控制来决定是否停止抓包
class GlobalControl(object):
    if_stopCapturing = None

throw_count = 0
recv_count = 0
def deal_packets(packet):
    global throw_count
    global recv_count
    try:
        IP_Layer = packet.payload
        Fourth_layer = IP_Layer.payload

        #recv_time = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(packet.time))
        recv_time = ("%.6f"%packet.time)[5:]
        length = len(str(packet))
        ether_dst = packet.dst
        ether_src = packet.src
        ip_dst = IP_Layer.dst
        ip_src = IP_Layer.src
     
        if(Fourth_layer.name == 'TCP' or Fourth_layer.name == 'UDP'):
            port_dst = Fourth_layer.dport
            port_src = Fourth_layer.sport      
            if(port_dst==53 or port_src==53):
                #DNS protocol
                fourthlayer_type = Fourth_layer.name + ' DNS'
            elif(port_dst==80 or port_src==80):
                if 'HTTP/1.1' in str(Fourth_layer.payload):
                    #HTTP protocol
                    fourthlayer_type = 'TCP HTTP'
                else:
                    #interact with gateway router
                    fourthlayer_type = Fourth_layer.name + ' HTTP'
            #fourthlayer_payload = str(Fourth_layer.payload)
            else:
                fourthlayer_type = Fourth_layer.name
        else:
            #e.g ICMP and other protocols
            fourthlayer_type = Fourth_layer.name
            port_dst = ''
            port_src = ''
            #fourthlayer_payload = str(Fourth_layer.payload)

        data = {'recv_time':recv_time,'length':length,
                'ether_dst':ether_dst,'ether_src':ether_src,
                'ip_dst':ip_dst,'ip_src':ip_src,
                'port_dst':port_dst,'port_src':port_src,
                'fourthlayer_type':fourthlayer_type,
                #'fourthlayer_payload':fourthlayer_payload,
               }
        packets.insert_one(data)
        recv_count += 1
    except:
        throw_count += 1
        #wrpcap("/home/DshtAnger/Music/"+str(throw_count)+".pcap",packet)

def stop_capture():
    if GlobalControl.if_stopCapturing:
        global throw_count
        global recv_count
        print "recv_count:",recv_count
        print "throw_count:",throw_count
        recv_count,throw_count = 0,0
        return 1
    else:
        return 0

def capturing():
    packets.drop()
    pkts = sniff(iface="wlan0",prn=lambda x:deal_packets(x),stop_filter=lambda x:stop_capture())
    #wrpcap("/home/DshtAnger/Music/pkts.pcap",pkts)
    exit()

# t = Thread(target=capturing,args=())
# t.start()


# class Packets(object):
#     def __init__(self):
#         self.__client = pymongo.MongoClient('127.0.0.1', 27017)
#         self.__sniffer = self.__client['sniffer']
#         self.__packets = self.__sniffer['packets']
#         self.__control = 0

#     def set_control(self,arg):
#         self.__control = arg

#     def get_control(self):
#         return self.__control

#     def __deal_packets(sele,packet):
#         try:
#             IP_Layer = packet.payload
#             Fourth_layer = IP_Layer.payload

#             ether_dst = packet.dst
#             ether_src = packet.src
#             ip_dst = IP_Layer.dst
#             ip_src = IP_Layer.src
#             dport = ''
#             sport = ''

#             if Fourth_layer.name == 'ICMP':
#                 fourthlayer_type = 'ICMP'
#                 fourthlayer_payload = Fourth_layer.payload.load        
#             elif Fourth_layer.name == 'TCP':
#                 fourthlayer_type = 'TCP'
#                 fourthlayer_payload = Fourth_layer.payload
#                 dport = Fourth_layer.dport
#                 sport = Fourth_layer.sport
#             else:
#                 fourthlayer_type = Fourth_layer.name
#                 fourthlayer_payload = Fourth_layer.payload


#             data = {'ether_dst':ether_dst,'ether_src':ether_src,'ip_dst':ip_dst,'ip_src':ip_src,
#                     'fourthlayer_type':fourthlayer_type,#'fourthlayer_payload':fourthlayer_payload,
#                     'dport':dport,'sport':sport}
#             __packets.insert_one(data)
#         except:
#             pass

#     def __stop_capture(self):
#         if __control:     
#             return 1
#         else:
#             return 0

#     def __running(self):
#         sniff(iface="wlan0",prn=lambda x:self.__deal_packets(x),stop_filter=lambda x:self.__stop_capture())
#         exit()
#     def capturing(self):
#         t = Thread(target=self.__running,args=())
#         t.start