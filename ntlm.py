import urllib2
from ntlm import HTTPNtlmAuthHandler   
# -*- coding: utf-8 -*-   
user = 'HPOWNER\test'   
password = "123"
url = "http://192.168.100.128/ovoweb/default.asp"   
   
passman = urllib2.HTTPPasswordMgrWithDefaultRealm()  
passman.add_password(None, url, user, password)
# create the NTLM authentication handler
auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)   
   
# create and install the opener 
opener = urllib2.build_opener(auth_NTLM) 
urllib2.install_opener(opener)
   
# retrieve the result
response = urllib2.urlopen(url)   
print(response.read())
