from bs4 import BeautifulSoup
import sys

soup=BeautifulSoup(open('msg_page13.html'),'lxml')

data=soup.table
table_soup=BeautifulSoup(str(data),'lxml')
s=table_soup.get_text()
print s.split()[0]
