#!/usr/bin/env python
import sys
from BeautifulSoup import BeautifulSoup
import pcapy
import re
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder

devs = pcapy.findalldevs()
#print "Devices List"
#for i in devs:
    #print "<%s>Dev:%s,Network:%s" %(devs.index(i),i,pcapy.open_live(i,0,0,0).getnet())
idx = 0 #raw_input("Your choice : ")
dev = devs[int(idx)]
out=""
p = pcapy.open_live(dev,1500,0,100)
p.setfilter("tcp port 80")
print "Listening on %s" %dev
# define a decoder to decode data
decoder = EthDecoder()
if pcapy.DLT_LINUX_SLL == p.datalink:
    decoder = LinuxSLLDecoder()

def pk(hdr,data):
  eth=decoder.decode(data)
  ip=eth.child()
  ipaddr=str(ip).splitlines()
  print ipaddr
  trans=ip.child()
  http=trans.child()
  array=str(trans).splitlines()
  s=""
  out=""
  pattern=re.compile('<nobr>.*?</nobr>')
  if len(array):
    for line in array:
      if line:
        s +=line[43:]

  #if re.match(re.compile('^(GET|HTTP)'),s):
  #  out +=s
  #else:
  #  out.join(s)
  #out +="\n"
  #print out
  if re.search("href=\"default.asp?",s):
    result=re.findall(pattern,s)
    s +="\n"
    #if result:
      #print result
  
try:
    p.loop(0,pk)
except KeyboardInterrupt:
    print "Terminated by user !"
    sys.exit(0)
  
