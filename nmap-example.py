from datetime import datetime
from peewee import *
import socket
from lxml.html import etree

def main():
#connect to the databases
	#change host to 127.0.0.1, add port 3306
	db = MySQLDatabase('ssl_check', host = 'db', user = 'root', password = '1234')
	#db = MySQLDatabase('ssl_check', host = '127.0.0.1', port = '3306', user = 'root', password = '1234')
	db.connect()

	#------------------------------------------------
	# Certification Class for DB 
	#------------------------------------------------
	class Cert(Model):
		start_time = DateTimeField() 
		end_time = DateTimeField() 
		host_ip = CharField()
		host_name = CharField()
		port_num = IntegerField()
		cert_ca = CharField()
		creation_date = DateTimeField()
		expiration_date = DateTimeField()

		class Meta:
			database = db

	db.create_tables([Cert])

	#----------------------------------------------------
	# Pulling values from the xml-to-dict (out.xml) file
	#----------------------------------------------------

	# pull values from dictionary
	tree = etree.parse('out.xml')
	results = tree.xpath('//host')

	for r in results:
		if r.xpath('.//table[@key="issuer"]/elem[@key="organizationName"]/text()'):
			my_start_time = datetime.fromtimestamp(int(r.xpath('./@starttime').pop()))
			my_end_time = datetime.fromtimestamp(int(r.xpath('./@endtime').pop()))
			my_host_ip = r.xpath('.//address[@addrtype="ipv4"]/@addr').pop()

			try:
				my_host_name = r.xpath('.//hostname/@name').pop()
			except:
				my_host_name = 'N/A'
			
		
			my_port_num  = r.xpath('.//@portid').pop()

			try:
				my_cert_ca = r.xpath('.//table[@key="issuer"]/elem[@key="organizationName"]/text()').pop()
			except:
				my_cert_ca = 'N/A'

			try:
				my_creation_date = datetime.strptime(r.xpath('.//table[@key="validity"]/elem[@key="notBefore"]/text()').pop(), "%Y-%m-%dT%H:%M:%S%z")
			except:
				my_creation_date = datetime.strptime(r.xpath('.//table[@key="validity"]/elem[@key="notBefore"]/text()').pop(), "%Y%m%d%H%M%SZ")

			try:
				my_expiration_date = datetime.strptime(r.xpath('.//table[@key="validity"]/elem[@key="notAfter"]/text()').pop(), "%Y-%m-%dT%H:%M:%S%z")
			except:
				my_expiration_date = 'N/A'

			'''
			# PRINT TO CONSOLE (check)
			print()
			print('Start time: ', my_start_time)
			print('End time: ', my_end_time)
			print('Host IP: ', my_host_ip)
			print('Hostname: ', my_host_name) 
			print('Port Number: ', my_port_num)
			print('Cert CA: ', my_cert_ca)
			print('Cert Creation Date: ', my_creation_date)
			print('Cert Expiration Date: ', my_expiration_date)
			print()
			'''
		
			'''
			# CREATING ROW: putting saved values into DB Cert table
			Cert.create(start_time = my_start_time, end_time = my_end_time, host_ip = my_host_ip, 
				host_name = my_host_name,  port_num = my_port_num, cert_ca = my_cert_ca, 
				creation_date = my_creation_date, expiration_date = my_expiration_date)
			'''
if __name__ == "__main__":
        main()

#----------------------------------------------------
# TO DO:
#----------------------------------------------------
# add / rework code with a main function / methods (Model View Control?)
# main (to be added)

'''
OVERALL
!! TO DO !!

PHASE 1: Database 
- add main / method calls 
- fix the parsing

PHASE 2: Web
- how to insert the DB rows into the web page 

PHASE 3: Email
- TBD


'''

'''
  web:
    container_name: web
    volumes:
      - C:\TPM:/
'''