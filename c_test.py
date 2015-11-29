#coding=utf-8
import socket
from struct import *
import datetime
import pcapy
import sys
import re
from bs4 import BeautifulSoup

def main(argv):
  #list all devices
  devs = pcapy.findalldevs()
  #print "Devices List"
  #for i in devs:
    #print "<%s>Dev:%s,Network:%s" %(devs.index(i),i,pcapy.open_live(i,0,0,0).getnet())
  idx = 0 #raw_input("Your choice : ")
  dev = devs[int(idx)]
	
  '''
  open device
  # Arguments here are:
  #   device
  #   snaplen (maximum number of bytes to capture _per_packet_)
  #   promiscious mode (1 for true)
  #   timeout (in milliseconds)
  '''
  cap = pcapy.open_live(dev , 65536 , 1 , 0)
  cap.setfilter("tcp port 80")
  print "Listening on %s" %dev
  http_pattern=re.compile('HTTP/1.1')
  page_pattern=re.compile(r'<html xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:msgs="ovow_webconsole" xmlns:userdate="ovow_webconsole_date">.*?</html>',re.S)
  #start sniffing packets
  html_count=0
  html_dic={}
  html_list=[]
  while(1) :
    (header, packet) = cap.next()
    #print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
    http_packet=parse_packet(packet)
    if http_packet:
      if re.search(http_pattern,http_packet):
        if html_count !=0:
          html=re.findall(page_pattern,html_dic[html_count])
          html_dic={}
          if html:
            #html_filename="msg_page"+str(html_count)+".html"
            #html_file=file(html_filename,'w+')
            #html_file.write(html[0])
            #html_file.close()
            #print html_filename
            #print html[0]
            print html[0]
            soup=BeautifulSoup(html[0],'lxml')
            print soup.prettify().decode('utf-8','ignore')
            table_html=soup.table
            table_soup=BeautifulSoup(str(table_html),'lxml')
            table_txt=table_soup.get_txt()
            print table_txt.split()
            #print html_dic[html_count]            
        html_count +=1
      if html_dic.has_key(html_count):
        html_dic[html_count] +=http_packet
      else:
        html_dic[html_count]=http_packet
      

#function to parse a packet
def parse_packet(packet) :	
  #parse ethernet header
  eth_length = 14
    
  #eth_header = packet[:eth_length]
  #eth = unpack('!6s6sH' , eth_header)
  #eth_protocol = socket.ntohs(eth[2])
  #print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

  #Parse IP packets, IP Protocol number = 8
  #if eth_protocol == 8 :
  #Parse IP header
  #take first 20 characters for the ip header
  ip_header = packet[eth_length:20+eth_length]
		
  #now unpack them :)
  iph = unpack('!BBHHHBBH4s4s' , ip_header)

  version_ihl = iph[0]
  #version = version_ihl >> 4
  ihl = version_ihl & 0xF

  iph_length = ihl * 4

  #ttl = iph[5]
  #protocol = iph[6]
  s_addr = socket.inet_ntoa(iph[8]);
  #d_addr = socket.inet_ntoa(iph[9]);
  #just want the packet from server
  if s_addr=="192.168.100.128":
    #print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
    t = iph_length + eth_length
    tcp_header = packet[t:t+20]

    #now unpack them :)
    tcph = unpack('!HHLLBBHHH' , tcp_header)
			
    #source_port = tcph[0]
    #dest_port = tcph[1]
    #sequence = tcph[2]
    #acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
			
    #print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
			
    h_size = eth_length + iph_length + tcph_length * 4
    data_size = len(packet) - h_size
			
    #get data from the packet
    tcp_data = packet[h_size:]		
    return tcp_data

if __name__ == "__main__":
  main(sys.argv)
