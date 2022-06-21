from ast import For
from cmath import log
#from ctypes import FormatError
from datetime import datetime
from peewee import *
from lxml import etree
import logging

def main():
    print("nmap running")
    logging.basicConfig(filename='nmap_log_test.log', encoding='utf-8', level=logging.DEBUG)
    logging.info('Trying to connect to db.')
    
    #connect to the mySQL database
    #try:
    db = MySQLDatabase('ssl_check', host = 'db', user = 'root', password = '1234')
    db.connect()
    #except Exception as e:
    #    logging.error("Exception occurred", exc_info=True)

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

    logging.info('Parsing out.xml file')
    #parse out fields from nmap scan
    tree = etree.parse('/tmp/out.xml')
    results = tree.xpath('//host')
    not_before   = './/table[@key="validity"]/elem[@key="notBefore"]/text()'
    not_after    = './/table[@key="validity"]/elem[@key="notAfter"]/text()'
    issuer_name  = './/table[@key="issuer"]/elem[@key="organizationName"]/text()'
    subject_name = './/table[@key="subject"]/elem[@key="organizationName"]/text()'

    for r in results:
        if r.xpath('.//table[@key="issuer"]/elem[@key="organizationName"]') and (r.xpath(issuer_name).pop() != r.xpath(subject_name).pop()):   
            start_time = datetime.fromtimestamp(int(r.xpath('./@starttime').pop()))
            end_time = datetime.fromtimestamp(int(r.xpath('./@endtime').pop()))
            host_ip = r.xpath('.//address[@addrtype="ipv4"]/@addr').pop()

            try:
                host_name = r.xpath('.//hostname/@name').pop()
            except Exception as e:
                logging.error("Exception occurred", exc_info=True)
            
            port_num_obj = r.xpath('.//port[.//table[@key="issuer"]/elem[@key="organizationName"]]')       

            for p in port_num_obj:

                port_num = (p.xpath('./@portid').pop())

                cert_ca = p.xpath(issuer_name).pop()
                
                try:
                    creation_date = datetime.strptime(p.xpath(not_before).pop(), "%Y-%m-%dT%H:%M:%S%z")
                #except FormatError:
                    #creation_date = datetime.strptime(p.xpath(not_before).pop(), "%Y%m%d%H%M%SZ")   # 10.244.8.13 str that didnt parse
                except Exception as e:
                    logging.error("Exception occurred", exc_info=True)

                try:
                    expiration_date = datetime.strptime(p.xpath(not_after).pop(), "%Y-%m-%dT%H:%M:%S%z")
                #except FormatError:
                    #expiration_date = datetime.strptime(p.xpath(not_after).pop(), "%Y%m%d%H%M%SZ")  # 10.241.64.101 str didnt parse
                except Exception as e:
                    logging.error("Exception occurred", exc_info=True)
                
                #logging.info('Adding row into db')
                #insert row into db
                Cert.create(start_time = start_time, end_time = end_time, host_ip = host_ip, host_name = host_name,  port_num = port_num, cert_ca = cert_ca, creation_date = creation_date, expiration_date = expiration_date)
        else:
            logging.error('No CA found')
    logging.info("Finished parsing.")
if __name__ == '__main__':
    main()