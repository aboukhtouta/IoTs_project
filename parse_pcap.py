#!/usr/bin/env python
'''

	Iot Sentinel: parse_pcap.py
	Author: Andy Pitcher <andy.pitcher@mail.concordia.ca>
	SHa1: 295451f0e54acb44cb7baa1b0f439df3041fc746

'''

import datetime
import time
import dpkt
import sys
import socket
import win_inet_pton
import pandas
import numpy as np
import glob, os
from struct import *
import argparse

'''
	Added by Amine Boukhtouta to get full path of PCAP files
	Added by Amine Boukhtouta to consider paths and dynamic sliding packet
	
	parser = argparse.ArgumentParser(description='IoT Sentinel Parse Pcaps')
	parser.add_argument('-m','--mode', default=1, type=int, choices = [0,1], help='mode 0: static, 1: dynamic')
	parser.add_argument('-p','--path', nargs='?', default ='./pcaps', help='path of PCAP traces')
	parser.add_argument('-o','--output', nargs='?', default ='./file_output', help='output path for CSVs')
	
	python parse_pcap.py -m 1 -p captures_IoT_Sentinel -o csv_results_offset
'''


def resource(filename):
	cwd = os.path.dirname(os.path.realpath(__file__))
	return os.path.join(cwd, filename)

"""
	Features applied to each packet %12
	
	f= 0 or 1

	f= number of new destination ip address

	f= port class ref 0 or 1 0r 2 or 3
		
"""

def ip_to_str(address):
	"""Print out an IP address given a string
	"""
	#return socket.inet_ntop(socket.AF_INET, address)
	return win_inet_pton.inet_ntop(socket.AF_INET, address)



def port_class_def(ip_port):
	"""
		no port => 0
		well known port [0,1023] => 1
		registered port [1024,49151] => 2
		dynamic port [49152,65535] => 3
	"""

	if 0 <= ip_port <= 1023:
		return 1
	elif  1024 <= ip_port <= 49151 :
		return 2
	elif 49152 <= ip_port <= 65535 :
		return 3
	else:
		return 0



def get_dest_ip_counter(L3_ip_dst_new):

	global L3_ip_dst_counter

	if L3_ip_dst_new not in L3_ip_dst_set:
		L3_ip_dst_set.append(L3_ip_dst_new)
		L3_ip_dst_counter = L3_ip_dst_counter + 1
	else:
		pass

	return L3_ip_dst_set,L3_ip_dst_counter





packet_number = 0
L3_ip_dst_set = []


def parse_pcap(capture,device_label,id_pcap):
	
	global packet_number

	i_counter=0
	f = open(capture,"rb")
	pcap = dpkt.pcap.Reader(f)


	for ts, buf in pcap:

	#Variables assignment

		L2_arp = 0
		L2_llc = 0

		L3_ip = 0
		L3_icmp = 0
		L3_icmp6 = 0
		L3_eapol = 0

		L4_tcp = 0
		L4_udp = 0

		L7_http = 0
		L7_https = 0
		L7_dhcp = 0
		L7_bootp = 0
		L7_ssdp = 0
		L7_dns = 0
		L7_mdns = 0
		L7_ntp = 0

		ip_padding = 0
		ip_ralert = 0
		ip_add_count = 0

		port_class_src = 0
		port_class_dst = 0

		pck_size = 0
		pck_rawdata = 0

		
		i_counter+=1
		#print (i_counter)
		
		#Assign ethernet buffer value to eth
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data

		

		#Network Layer IP
		if eth.type == dpkt.ethernet.ETH_TYPE_IP:
			L3_ip = 1

			#Get packet size
			pck_size = len(ip.data)

			#Check router alert (HL has to be above 5 and ip.opts == '\x94\x04\x00\x00')
			if ip.hl > 5:
				if ip.opts == dpkt.ip.IP_OPT_RALERT:
					ip_ralert=1

			#Check new destination IP
			ip_dst_new=ip_to_str(ip.dst)
			L3_ip_dst,L3_ip_dst_count=get_dest_ip_counter(ip_dst_new)


			tcp = ip.data
			udp = ip.data
			
		#Network Layer ICMP-ICMP6	 
			if type(ip.data) == dpkt.icmp.ICMP:
				L3_icmp = 1
			if type(ip.data) == dpkt.icmp6.ICMP6:
				L3_icmp6 = 1
			if type(ip.data) == dpkt.ip.IP_PROTO_RAW:
				pck_rawdata = 1
		
		#Transport UDP DHCP-DNS-MDNS-SSDP-NTP
			if type(ip.data) == dpkt.udp.UDP:
				L4_udp = 1
				port_class_src = port_class_def(udp.sport)
				port_class_dst = port_class_def(udp.dport)

				if udp.sport == 68 or udp.sport == 67 :
					L7_dhcp = 1
					L7_bootp = 1
				if udp.sport == 53 or udp.dport == 53 :
					L7_dns = 1
				if udp.sport == 5353 or udp.dport == 5353 :
					L7_mdns = 1
				if udp.sport == 1900 or udp.dport == 1900 :
					L7_ssdp = 1
				if udp.sport == 123 or udp.dport == 123 :
					L7_ntp = 1
		
		#Transport TCP HTTP-HTTPS
			if type(ip.data) == dpkt.tcp.TCP:
				L4_tcp = 1
				port_class_src = port_class_def(tcp.sport)
				port_class_dst = port_class_def(tcp.dport)

				if tcp.sport == 80 or tcp.dport == 80:
					L7_http = 1			   
				if tcp.sport == 443 or tcp.dport == 443:
					 L7_https = 1

		elif eth.type != dpkt.ethernet.ETH_TYPE_IP:
		
		#Data Link ARP-LLC
			if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
				L2_arp = 1			
			if eth.type == dpkt.llc.LLC:
				L2_llc= 1
		
		#Network EAPoL
			if eth.type == dpkt.ethernet.ETH_TYPE_EAPOL:
				L3_eapol = 1
		else:
			print (i,'\n\nNon IP Packet type not supported  %s\n') % eth.data.__class__.__name__
			#sys.exit(1)
			continue

	#Create the array containing the 23 features

		#Dataframe to be pushed into csvpck_size
		ar2={'ARP':[L2_arp],'LLC':[L2_llc],'EAPOL':[L3_eapol],'Pck_size':[pck_size],'Pck_rawdata':[pck_rawdata],'IP_padding':[ip_padding],'IP_ralert':[ip_ralert],'IP_add_count':[L3_ip_dst_counter],'Portcl_src':[port_class_src],'Portcl_dst':[port_class_dst],'ICMP':[L3_icmp],'ICMP6':[L3_icmp6],'TCP':[L4_tcp],'UDP':[L4_udp],'HTTPS':[L7_https],'HTTP':[L7_http],'DHCP':[L7_dhcp],'BOOTP':[L7_bootp],'SSDP':[L7_ssdp],'DNS':[L7_dns],'MDNS':[L7_mdns],'NTP':[L7_ntp],'Label': [device_label]}
		headers_name=['ARP','LLC','EAPOL','Pck_size','Pck_rawdata','IP_padding','IP_ralert','IP_add_count','Portcl_src','Portcl_dst','ICMP','ICMP6','TCP','UDP','HTTPS','HTTP','DHCP','BOOTP','SSDP','DNS','MDNS','NTP','Label'] 
		df2= pandas.DataFrame(data=ar2,columns=headers_name)
	   
		print (ar2)
		label_folder=out+os.sep+device_label
		#csv_file='csv_results_5/'+device_label+'/file_'+device_label+'_'+str(id_pcap)+'.csv'
		if not os.path.exists(label_folder):
			os.makedirs(label_folder)
			
		csv_file=label_folder+os.sep+'file_'+device_label+'_'+str(id_pcap)+'.csv'
		df2.to_csv(csv_file, sep='\t', encoding='utf-8',mode='a', header=False)

		print ("\n")
		packet_number+=1
	f.close()

def get_nbr_packets(capture):
	cpt=0
	f = open(capture,"rb")
	pcap = dpkt.pcap.Reader(f)
	for ts, buf in pcap:
		cpt=cpt+1
	f.close()
	return cpt
	
def parse_pcap_offset(capture,device_label,id_pcap,offset):
	
	global packet_number

	i_counter=0
	f = open(capture,"rb")
	pcap = dpkt.pcap.Reader(f)

	cpt=1
	for ts, buf in pcap:
		if cpt<offset:
			cpt=cpt+1
	#Variables assignment
		else:
			L2_arp = 0
			L2_llc = 0

			L3_ip = 0
			L3_icmp = 0
			L3_icmp6 = 0
			L3_eapol = 0

			L4_tcp = 0
			L4_udp = 0

			L7_http = 0
			L7_https = 0
			L7_dhcp = 0
			L7_bootp = 0
			L7_ssdp = 0
			L7_dns = 0
			L7_mdns = 0
			L7_ntp = 0

			ip_padding = 0
			ip_ralert = 0
			ip_add_count = 0

			port_class_src = 0
			port_class_dst = 0

			pck_size = 0
			pck_rawdata = 0

			
			i_counter+=1
			print (i_counter)
			
			#Assign ethernet buffer value to eth
			eth = dpkt.ethernet.Ethernet(buf)
			ip = eth.data

			#Network Layer IP
			if eth.type == dpkt.ethernet.ETH_TYPE_IP:
				L3_ip = 1

				#Get packet size
				pck_size = len(ip.data)

				#Check router alert (HL has to be above 5 and ip.opts == '\x94\x04\x00\x00')
				if ip.hl > 5:
					if ip.opts == dpkt.ip.IP_OPT_RALERT:
						ip_ralert=1

				#Check new destination IP
				ip_dst_new=ip_to_str(ip.dst)
				L3_ip_dst,L3_ip_dst_count=get_dest_ip_counter(ip_dst_new)


				tcp = ip.data
				udp = ip.data
				
			#Network Layer ICMP-ICMP6	 
				if type(ip.data) == dpkt.icmp.ICMP:
					L3_icmp = 1
				if type(ip.data) == dpkt.icmp6.ICMP6:
					L3_icmp6 = 1
				if type(ip.data) == dpkt.ip.IP_PROTO_RAW:
					pck_rawdata = 1
			
			#Transport UDP DHCP-DNS-MDNS-SSDP-NTP
				if type(ip.data) == dpkt.udp.UDP:
					L4_udp = 1
					port_class_src = port_class_def(udp.sport)
					port_class_dst = port_class_def(udp.dport)

					if udp.sport == 68 or udp.sport == 67 :
						L7_dhcp = 1
						L7_bootp = 1
					if udp.sport == 53 or udp.dport == 53 :
						L7_dns = 1
					if udp.sport == 5353 or udp.dport == 5353 :
						L7_mdns = 1
					if udp.sport == 1900 or udp.dport == 1900 :
						L7_ssdp = 1
					if udp.sport == 123 or udp.dport == 123 :
						L7_ntp = 1
			
			#Transport TCP HTTP-HTTPS
				if type(ip.data) == dpkt.tcp.TCP:
					L4_tcp = 1
					port_class_src = port_class_def(tcp.sport)
					port_class_dst = port_class_def(tcp.dport)

					if tcp.sport == 80 or tcp.dport == 80:
						L7_http = 1			   
					if tcp.sport == 443 or tcp.dport == 443:
						 L7_https = 1

			elif eth.type != dpkt.ethernet.ETH_TYPE_IP:
			
			#Data Link ARP-LLC
				if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
					L2_arp = 1			
				if eth.type == dpkt.llc.LLC:
					L2_llc= 1
			
			#Network EAPoL
				if eth.type == dpkt.ethernet.ETH_TYPE_EAPOL:
					L3_eapol = 1
			else:
				print (i,'\n\nNon IP Packet type not supported  %s\n') % eth.data.__class__.__name__
				#sys.exit(1)
				continue

		#Create the array containing the 23 features

			#Dataframe to be pushed into csvpck_size
			ar2={'ARP':[L2_arp],'LLC':[L2_llc],'EAPOL':[L3_eapol],'Pck_size':[pck_size],'Pck_rawdata':[pck_rawdata],'IP_padding':[ip_padding],'IP_ralert':[ip_ralert],'IP_add_count':[L3_ip_dst_counter],'Portcl_src':[port_class_src],'Portcl_dst':[port_class_dst],'ICMP':[L3_icmp],'ICMP6':[L3_icmp6],'TCP':[L4_tcp],'UDP':[L4_udp],'HTTPS':[L7_https],'HTTP':[L7_http],'DHCP':[L7_dhcp],'BOOTP':[L7_bootp],'SSDP':[L7_ssdp],'DNS':[L7_dns],'MDNS':[L7_mdns],'NTP':[L7_ntp],'Label': [device_label]}
			headers_name=['ARP','LLC','EAPOL','Pck_size','Pck_rawdata','IP_padding','IP_ralert','IP_add_count','Portcl_src','Portcl_dst','ICMP','ICMP6','TCP','UDP','HTTPS','HTTP','DHCP','BOOTP','SSDP','DNS','MDNS','NTP','Label'] 
			df2= pandas.DataFrame(data=ar2,columns=headers_name)
		   
			print (ar2)

			#csv_file='csv_results_5/'+device_label+'/file_'+device_label+'_'+str(id_pcap)+'.csv'
			label_folder=out+os.sep+device_label
			if not os.path.exists(label_folder):
				os.makedirs(label_folder)
			csv_file=label_folder+os.sep+'file_'+device_label+'_'+str(id_pcap)+'_'+str(offset)+'.csv'
			df2.to_csv(csv_file, sep='\t', encoding='utf-8',mode='a', header=False)

			print ("\n")
			packet_number+=1
	f.close()	
	
def main():

	parser = argparse.ArgumentParser(description='IoT Sentinel Parse Pcaps')
	parser.add_argument('-m','--mode', default=1, type=int, choices = [0,1], help='mode 0: static, 1: dynamic')
	parser.add_argument('-p','--path', nargs='?', default ='./file.csv', help='path of PCAP traces')
	parser.add_argument('-o','--output', nargs='?', default ='./file_output', help='output path for CSVs')
	#A]TO parse one pcap --> uncomment A and comment B : need to implement arguments

	# filename_path='/home/andyp/Documents/Studies/CONCORDIA/IoT_project/IoT_Sentinel/src/captures_IoT_Sentinel/captures_IoT-Sentinel/Aria/Setup-A-1-STA.pcap'
	# device_label='Aria'
	# id_pcap=1
	# global L3_ip_dst_counter
	# L3_ip_dst_counter=1
	# parse_pcap(filename_path,device_label,id_pcap)


	#B]TO parse several pcaps

	global L3_ip_dst_counter
	global out
	if len(sys.argv)>1:
		#start_time = time.time()
		args = parser.parse_args()
		p=resource(args.path)
		out=resource(args.output)
		if not os.path.exists(out):
			os.makedirs(out)
		device_label=sorted(os.listdir(p))
		i = 0
		id_pcap=0
		if args.mode==0:
			while i < len(device_label):
				#filename_path='/home/andyp/Documents/Studies/CONCORDIA/IoT_project/IoT_Sentinel/src/captures_IoT_Sentinel/captures_IoT-Sentinel/'+device_label[i]+'/*.pcap'
				filename_path=p+os.sep+device_label[i]+os.sep+"*.pcap"
				for filename in glob.glob(filename_path):
					if os.path.isfile(filename):
						del L3_ip_dst_set[:]
						L3_ip_dst_counter = 1 
						print (L3_ip_dst_set,L3_ip_dst_counter)
						parse_pcap(filename,device_label[i],id_pcap)
						id_pcap += 1
					else:
						print('file does not exist')
				i += 1
		elif args.mode==1: # with sliding packets
			while i < len(device_label):
				#filename_path='/home/andyp/Documents/Studies/CONCORDIA/IoT_project/IoT_Sentinel/src/captures_IoT_Sentinel/captures_IoT-Sentinel/'+device_label[i]+'/*.pcap'
				filename_path=p+os.sep+device_label[i]+os.sep+"*.pcap"
				#print filename_path
				for filename in glob.glob(filename_path):
					if os.path.isfile(filename): 
						#print (L3_ip_dst_set,L3_ip_dst_counter)
						#print get_nbr_packets(filename)
						#sys.exit(1)
						for offset in range(2,get_nbr_packets(filename)):
							del L3_ip_dst_set[:]
							L3_ip_dst_counter = 1
							parse_pcap_offset(filename,device_label[i],id_pcap,offset)
						id_pcap += 1
					else:
						print('file does not exist')
				i += 1
	else:
		print "Please refer to the following command help listing ..."
		parser.print_help()
		sys.exit(1)

if __name__== "__main__":
  main()