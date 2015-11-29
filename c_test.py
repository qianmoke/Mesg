import socket
from struct import *
import datetime
import pcapy
import sys
import re
import xlwt,xlrd
from xlutils.copy import copy
from bs4 import BeautifulSoup
from bs4 import UnicodeDammit

def main(argv):
  #list all devices
  devs = pcapy.findalldevs()
  #print "Devices List"
  #for i in devs:
    #print "<%s>Dev:%s,Network:%s" %(devs.index(i),i,pcapy.open_live(i,0,0,0).getnet())
  idx = 0 #raw_input("Your choice : ")
  dev = devs[int(idx)]
  xls_name="Mesg.xls"	
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
  #page_pattern=re.compile(r'<html xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:msgs="ovow_webconsole" xmlns:userdate="ovow_webconsole_date">.*?</html>',re.S)
  page_pattern=re.compile(r'<html xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:user="ovow_webconsole" xmlns:userdate="ovow_webconsole_date">.*?</html>',re.S)
  #start sniffing packets
  html_count=0
  html_dic={}
  mesg_dic={}
  mesg=[]
  mesg_writed=init(xls_name)
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
            mesg_all=collect_mesg_from_html(html)
            if mesg_all:
              mesg=choose_data_in_mesglist(mesg_all)
              time=mesg[2]
              if time not in mesg_dic.keys():
                mesg_dic[time]=[]
                for mesg_data in mesg:
                  mesg_dic[time].append(mesg_data)
                #print mesg_dic
                #print
                write_mesg_to_xls(mesg_writed,mesg_dic,xls_name)
                mesg_writed.append(time)
        html_count +=1
      if html_dic.has_key(html_count):
        html_dic[html_count] +=http_packet
      else:
        html_dic[html_count]=http_packet

#function to init mesg_writed:
def init(xls):
  wlist=[]
  today=str(datetime.date.today())
  xls_old=xlrd.open_workbook(xls)
  sheet=xls_old.sheet_by_name(today)
  for time in sheet.col(2):
    wlist.append(time.value)
  return wlist
  
#function write mesg to xls
def write_mesg_to_xls(wlist,dic,xls):
  today=str(datetime.date.today())
  xls_old=xlrd.open_workbook(xls)
  sheet_num=xls_old.nsheets
  xls_new=copy(xls_old)
  if today not in xls_old.sheet_names():
    sheet=xls_new.add_sheet(today)
    xls_new.save(xls)
    row=0
  else:
    sheet=xls_new.get_sheet(sheet_num-1)
    row=xls_old.sheet_by_name(today).nrows

  col=0
  for time in dic.keys():
    if time not in wlist:
      print wlist
      for mesg_data in dic[time]:
        sheet.write(row,col,mesg_data)
        col +=1
      col=0
      row +=1
      print "write messge:%s successful"%time
  xls_new.save(xls)
  
        
#fubction to collect mesg from html 
def collect_mesg_from_html(html):
  table_line=[]
  dammit = UnicodeDammit(html[0])
  html_data=dammit.unicode_markup
  #print dammit.original_encoding
  soup=BeautifulSoup(html_data,'lxml')
  #print soup.prettify()
  for table_html in soup.find_all('table'):
    if table_html.has_attr('cellpadding'):
      if table_html['cellpadding']=='0':
        #print table_html.attrs
        table_soup=BeautifulSoup(str(table_html),'lxml')
        table_text=table_soup.get_text() 
        return table_text.splitlines()

def choose_data_in_mesglist(mesg_list):
  title_list=[14,16,38,58]
  item_list=[15,17,39,62]
  mesg=[]
  for item in item_list:
    mesg.append(mesg_list[item])
  return mesg
    

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
