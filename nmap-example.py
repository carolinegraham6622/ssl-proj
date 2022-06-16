from datetime import datetime
from peewee import *
import socket
from lxml import etree

db = MySQLDatabase('ssl_check', host = 'db', user = 'root', password = '1234')
db.connect()

#------------------------------------------------
# Certification Class for DB (fix types)
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

tree = etree.parse('/tmp/out.xml')
results = tree.xpath('//host')
not_before   = './/table[@key="validity"]/elem[@key="notBefore"]/text()'
not_after    = './/table[@key="validity"]/elem[@key="notAfter"]/text()'
issuer_name  = './/table[@key="issuer"]/elem[@key="organizationName"]/text()'
subject_name = './/table[@key="subject"]/elem[@key="organizationName"]/text()'

for r in results:
    if r.xpath('.//table[@key="issuer"]/elem[@key="organizationName"]') and (r.xpath(issuer_name).pop() != r.xpath(subject_name).pop()):    # only check hosts that have an entry for CA
        start_time = datetime.fromtimestamp(int(r.xpath('./@starttime').pop()))
        end_time = datetime.fromtimestamp(int(r.xpath('./@endtime').pop()))
        host_ip = r.xpath('.//address[@addrtype="ipv4"]/@addr').pop()               # dont catch mac address, only ipv4

        try:
            host_name = r.xpath('.//hostname/@name').pop()
        except:
            host_name = 'N/A'                                                       # 150.250.77.58 no host name
        
        port_num_obj = r.xpath('.//port[.//table[@key="issuer"]/elem[@key="organizationName"]]')        # if there is an entry for CA, get port number
                                                                                                        # returns only first one it sees now (runs backwards to xml)
        for p in port_num_obj:

            port_num = (p.xpath('./@portid').pop())

            cert_ca = p.xpath(issuer_name).pop()
            
            try:
                creation_date = datetime.strptime(p.xpath(not_before).pop(), "%Y-%m-%dT%H:%M:%S%z")
            except:
                creation_date = datetime.strptime(p.xpath(not_before).pop(), "%Y%m%d%H%M%SZ")   # 10.244.8.13 str that didnt parse

            try:
                expiration_date = datetime.strptime(p.xpath(not_after).pop(), "%Y-%m-%dT%H:%M:%S%z")
            except:
                expiration_date = datetime.strptime(p.xpath(not_after).pop(), "%Y%m%d%H%M%SZ")  # 10.241.64.101 str didnt parse
            
            Cert.create(start_time = start_time, end_time = end_time, host_ip = host_ip, host_name = host_name,  port_num = port_num, cert_ca = cert_ca, creation_date = creation_date, expiration_date = expiration_date)