from datetime import datetime, timedelta, tzinfo
from email.message import EmailMessage
from sys import exc_info
from peewee import *
from lxml import etree
import pymysql
import logging
from logging.handlers import TimedRotatingFileHandler
import smtplib
from textwrap import dedent

# global db
db = MySQLDatabase(database='ssl_check', host = 'db', user = 'root', password = '1234')

def main():
	# create db connection
	db.connect()
	# create table in db
	db.create_tables([CertModel])
	logger = get_logger()
	cert_list = parse_xml(logger)
	create_cert_entry(cert_list, logger)
	send_email(cert_list, logger)

class CertModel(Model):
	"""
    A class to represent a SSL certification 

    ...

    Attributes
    ----------
    start_time : DateTimeField
        timestamp of when the nmap scan started to run
    end_time : DateTimeField
        timestamp of when the nmap finished scanning host
    host_ip : CharField()
		ip address of host
	host_name : CharField()
		name assigned to device connect on network
	port_num = IntegerField()
		specified port of ip address
	issuer_name : CharField()
		Certification CA
	creation_date : DateTimeField()
		timestamp of when SSL certification was created
	expiration_date : DateTimeField()
		timestamp of when SSL certification expires
	expires_in : IntegerField()
		how long (in days) before certification expires
	"""
	start_time = DateTimeField() 
	end_time = DateTimeField()
	host_ip = CharField()
	host_name = CharField()
	port_num = IntegerField()
	issuer_name = CharField()
	creation_date = DateTimeField()
	expiration_date = DateTimeField() 
	expires_in = IntegerField()

	class Meta:
		database = db

class Cert:
	def __init__(self, *args, **kwargs):
		# self.start_time = kwargs.get('start_time', None)
		self.start_time = kwargs['start_time']
		self.end_time = kwargs['end_time']
		self.host_ip = kwargs['host_ip']
		self.host_name = kwargs['host_name']
		self.port_num = kwargs['port_num']
		self.issuer_name = kwargs['issuer_name']
		self.creation_date = kwargs['creation_date']
		self.expiration_date = kwargs['expiration_date']
		self.expires_in = kwargs['expires_in']

	def __str__(self):
		# dedent for logging
		return (dedent(f"""\
                Start time: {self.start_time}
                End time:  {self.end_time}
                Host IP: {self.host_ip}
                Hostname: {self.host_name}
                Port Number: {self.port_num}
                Cert CA: {self.issuer_name}
                Cert Creation Date: {self.creation_date}"""))

	def __eq__(self, __o: object):
		return (self.host_ip == __o.host_ip and self.host_name == __o.host_name and
				self.port_num == __o.port_num and self.issuer_name == __o.issuer_name and
				self.creation_date == __o.creation_date and self.expiration_date == __o.expiration_date
				and self.expires_in == __o.expires_in)

def get_logger():
	'''
    Creates new formatted logger, creates log file example.log in tmp folder and returns logger

            Returns:
                    logger (Logger): formatted logger
    '''

	# create logger
	logger = logging.getLogger(__name__)
	logger.setLevel(logging.DEBUG)

	# create console handler and set level to debug
	fh = logging.handlers.TimedRotatingFileHandler('/tmp/example.log', when='midnight', interval=1, backupCount=3650) 
	fh.setLevel(logging.DEBUG)

	# create formatter
	formatter = logging.Formatter('%(asctime)s|%(levelname)s|%(funcName)s|%(lineno)d|%(message)s')

	# add formatter to handler
	fh.setFormatter(formatter)

	# add handler to logger
	logger.addHandler(fh)

	return logger


def parse_xml(logger):
	'''
    parses the out.xml file created from nmap scan, creates cert entry and returns cert_list

            Parameters:
                    logger (Logger): formatted logger

            Returns:
                    cert_list (list): list of certification entries w/o duplicates and sorted by expiration
    '''
	#fmt1 - returned by linux scan, fmt2 - returned by windows scan, fmt3 - some entries from linux scan didnt parse correctly, none for valid ssl's but this has been left
	def try_strptime(s, formats=['%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S', '%Y%m%d%H%M%SZ']):
		for fmt in formats:
			try:
				return datetime.strptime(s, fmt)
			except:
				logger.debug(f'Failed to parse datetime obj from string - {s} using format - {fmt}', exc_info=True)
				continue
		raise ValueError

	xml_doc_path = '/tmp/out.xml'
	cert_list = [] # list that will hold all unique certs found

	try:
		tree = etree.parse(xml_doc_path) 
		logger.debug(f'XML doc found at {xml_doc_path}')
	except:
		logger.critical(f'XML doc not found at {xml_doc_path}', exc_info=True)

	try:
		results = tree.xpath('//host')
	except:
		logger.critical('No hosts found', exc_info=True)

	logger.debug(f'{len(results)} hosts found')

	#saved paths
	issuer_path = './/table[@key="issuer"]/elem[@key="organizationName"]/text()'
	subject_path = './/table[@key="subject"]/elem[@key="organizationName"]/text()'
	host_ip_path = './/address[@addrtype="ipv4"]/@addr'									# dont catch mac address
	host_name_path = './/hostname/@name'

	# for each host found
	for r in results:
		try:
			host_ip = r.xpath(host_ip_path).pop()					
		except:
			logger.error(f'No ipv4 address found at {host_ip_path}', exc_info=True)
			host_ip = 'HOST ADDRESS NOT FOUND'

		ssl_ports = r.xpath('.//port[.//table[@key="issuer"]/elem[@key="organizationName"]]')   # only show ports with an entry for issuer, returns empty list otherwise

		if ssl_ports:
			logger.debug(f'{host_ip} has ssl cert(s)')
			
			#for each port found in host
			for p in ssl_ports:

					# issuer_name
					try:
						issuer_name  = p.xpath(issuer_path).pop()
					except:
						logger.error(f'No issuer name found at {issuer_path}', exc_info=True)
						issuer_name  = 'NONE FOUND'

					# subject_name
					try:
						subject_name = p.xpath(subject_path).pop()
					except:
						logger.error(f'No subject name found at {subject_path}', exc_info=True)
						subject_name  = 'NONE FOUND'						

					# proceed to parsing rest of fields if not a self-signed certificate
					if (issuer_name != subject_name):

						# port_num
						port_num = (p.xpath('./@portid').pop())
						logger.info(f'found cert {issuer_name}/{subject_name} on {host_ip}/{port_num}')

						# start_time
						try:
							start_time = datetime.fromtimestamp(int(r.xpath('./@starttime').pop()))
						except:
							logger.error(f'Failed to grab start time for {host_ip}/{port_num} at ./@starttime', exc_info=True)
							start_time = datetime.min

						# end_time
						try:
							end_time = datetime.fromtimestamp(int(r.xpath('./@endtime').pop()))
						except:
							logger.error(f'Failed to grab end time for {host_ip}/{port_num} at ./@endtime', exc_info=True)
							end_time = datetime.min

						# host_name
						try:
							host_name = r.xpath(host_name_path).pop()
						except:
							logger.error(f'No host name found for {host_ip} at {host_name_path}', exc_info=True)
							host_name = 'NOT FOUND'
						
						# creation_date
						try:
							not_before = p.xpath('.//table[@key="validity"]/elem[@key="notBefore"]/text()').pop()
							creation_date = (try_strptime(not_before)).replace(tzinfo=None)
						except ValueError:
							logger.warning(f'{host_ip} - creation date did not parse correctly into xml\nGiven string: {not_before}')
						except:
							logger.error(f'Failed to grab creation date at .//table[@key="validity"]/elem[@key="notBefore"]/text()', exc_info=True)
							creation_date = (datetime.min).replace(tzinfo=None)

						# expiration_date
						try:
							not_after  = p.xpath('.//table[@key="validity"]/elem[@key="notAfter"]/text()').pop()
							expiration_date = (try_strptime(not_after)).replace(tzinfo=None)
						except ValueError:
							logger.warning(f'{host_ip} - expiration date did not parse correctly into xml\nGiven string: {not_after}')
						except:
							logger.error(f'Failed to grab expiration date at .//table[@key="validity"]/elem[@key="notBefore"]/text()', exc_info=True)
							expiration_date = (datetime.min).replace(tzinfo=None)

						# expires_in
						try:
							days_till_expire = int((expiration_date - datetime.now()).days)
						except:
							logger.error(f'Failed to calculate days until expiration date from expiration date at .//table[@key="validity"]/elem[@key="notBefore"]/text()', exc_info=True)
							days_till_expire = -9000
						
						# creating new cert entry 
						new_cert = Cert(start_time = start_time, end_time=end_time, host_ip=host_ip, host_name=host_name,\
							port_num=port_num, issuer_name=issuer_name, creation_date=creation_date, expiration_date=expiration_date, expires_in=days_till_expire)

						# throw out any duplicated certs
						if new_cert not in cert_list:
							cert_list.append(new_cert)
							logger.info(f'Cert added to list - \n{new_cert}')
						else:
							logger.debug(f'Duplicate entry found, omitting from list {new_cert}')
					else:
                        # this first line seems to need to be blank so every following line has same whitespace for dedent
						logger.debug(dedent(f'''\
											Self-signed certificate found for {host_ip}
											Issuer : {issuer_name}
											Subject: {subject_name}'''))
		# no cert found/added to cert_list, move on to next
		else:
			logger.debug(f'No certificate(s) found on {host_ip}')

	#parsing completed, sort the list by expiration date
	cert_list.sort(key=lambda x: x.expiration_date)

	return cert_list

def create_cert_entry(cert_list, logger):
	'''
    Populates the database CertModel with certs found in cert_list

            Parameters:
					cert_list (list): sorted list of unique certifications (w/o duplicated values), sorted by expiration date
                    logger (Logger): formatted logger

            Returns:
                    N/A
    '''
	for cert in cert_list:

		CertModel.create(start_time = cert.start_time, end_time = cert.end_time, host_ip = cert.host_ip, host_name = cert.host_name,  \
			port_num = cert.port_num, issuer_name = cert.issuer_name, creation_date = cert.creation_date, expiration_date = cert.expiration_date, expires_in = cert.expires_in)

		logger.info(f'Table entry created \n{cert}')		

def send_email(cert_list, logger):
	'''
    Pushes email w/ html table of certifications to specified email address

            Parameters:
					cert_list (list): sorted list of unique certifications (w/o duplicated values), sorted by expiration date
                    logger (Logger): formatted logger

            Returns:
                    N/A
    '''

	oldest_date = 180
	email_list = []
	now = datetime.now()
	one_year = timedelta(days = 365)

	msg = EmailMessage()
	msg['Subject'] = 'SSL certificates expiring'
	msg['From'] = 'SSL Certificate Scanner <noreply@rowan.edu>'
	msg['To'] = ('graham26@rowan.edu')

	message = f"""
	<head>This list includes all discovered certificates that have expired in the past {oldest_date} days, or will expire in the next 365 days:</head>
	<table border="1" width="80%">
		<tr>
			<th>Host Name</th>
			<th>Port #</th>
			<th>Days till Expiration</th>
			<th>Certificate Authority</th>
			<th>Expiration Date</th>
		</tr>
	"""

	for cert in cert_list:
		expiry_date = cert.expiration_date
		if now + one_year > expiry_date:
			days_till_expire = (expiry_date - now).days
			if days_till_expire >= -(oldest_date):
				email_list.append(f"""
								<tr>
									<td>{cert.host_name}</td>
									<td>{cert.port_num}</td>
									<td>{days_till_expire}</td>
									<td>{cert.issuer_name}</td>
									<td>{cert.expiration_date.date()}</td>
								</tr>
								""")

				logger.info(f'Following cert was added to email message \n{cert}')
			else:
				logger.info(f'Following cert was not added to email, is more than {oldest_date} days expired \n{cert}')

	# sort list of strings by splitting them, and casting the 4th indice (days_till_expire) into int, then sorting by that int
	
	for e in email_list:
		message += e

	message += """
	</table>
	"""

	logger.info(f'Message being sent, \n{message}')
	
	try:   
		# port 25 is smtp port
		smtp_obj = smtplib.SMTP('mail.rowan.edu', 25)
		msg.set_content(message, subtype = 'html')
		smtp_obj.send_message(msg) 
		print("Emails sent")
		logger.debug("Emails sent")
	except smtplib.SMTPException:
		print("Emails not sent")
		logger.critical("Failed to send emails", exc_info=True)

if __name__ == '__main__': 
	main()

			
			
















