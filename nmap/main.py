import smtplib
import logging
from peewee import *
from lxml import etree
from textwrap import dedent
from models import CertModel, Cert, db
from email.message import EmailMessage
from datetime import datetime, timedelta

def main():
	
	# TODO: delete 
	# create db connection
	# db.connect()
	# db.create_tables([CertModel])

	# establish sqlalchemy db connection
	# database_connect()
	
	# parse the xml generated from the nmap scan, send email of found expiring certificates
	list_of_certificates = parse_xml()
	# create_cert_entry(list_of_certificates) #TODO: refactor the database 
	
	send_email(list_of_certificates, expired=False)
	send_email(list_of_certificates, expired=True)

def parse_xml():
	"""
    Parses the out.xml file created from nmap scan, creates cert entry and returns a list of certificates

		Returns:
				list_of_certificates (list): list of certification entries w/o duplicates and sorted by expiration
	"""

	def try_strptime(s, formats=['%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S', '%Y%m%d%H%M%SZ']):
		for fmt in formats:
			try:
				return datetime.strptime(s, fmt)
			except:
				logging.debug(f'Failed to parse datetime obj from string - {s} using format - {fmt}', exc_info=True)
				continue
		raise ValueError

	xml_doc_path = '/tmp/out.xml'
	list_of_certificates = []

	try:
		tree = etree.parse(xml_doc_path) 
		logging.debug(f'XML doc found at {xml_doc_path}')
	except:
		logging.critical(f'XML doc not found at {xml_doc_path}', exc_info=True)

	try:
		results = tree.xpath('//host')
	except:
		logging.critical('No hosts found', exc_info=True)

	logging.debug(f'{len(results)} hosts found')

	#saved paths
	issuer_path = './/table[@key="issuer"]/elem[@key="organizationName"]/text()'
	subject_path = './/table[@key="subject"]/elem[@key="organizationName"]/text()'
	host_ip_path = './/address[@addrtype="ipv4"]/@addr'									# dont catch mac address
	host_name_path = './/hostname/@name'

	# traverse through each host that was found
	for host in results:
		try:
			host_ip = host.xpath(host_ip_path).pop()					
		except:
			logging.error(f'No ipv4 address found at {host_ip_path}', exc_info=True)
			host_ip = 'HOST ADDRESS NOT FOUND'

		ssl_ports = host.xpath('.//port[.//table[@key="issuer"]/elem[@key="organizationName"]]')   # only show ports with an entry for issuer, returns empty list otherwise

		if ssl_ports:
			logging.debug(f'{host_ip} has ssl cert(s)')
			
			# traverse each port found in host
			for p in ssl_ports:

					# issuer_name
					try:
						issuer_name  = p.xpath(issuer_path).pop()
					except:
						logging.error(f'No issuer name found at {issuer_path}', exc_info=True)
						issuer_name  = 'NONE FOUND'

					# subject_name
					try:
						subject_name = p.xpath(subject_path).pop()
					except:
						logging.error(f'No subject name found at {subject_path}', exc_info=True)
						subject_name  = 'NONE FOUND'						

					# proceed to parsing rest of fields if not a self-signed certificate
					if (issuer_name != subject_name):

						# port_num
						port_num = (p.xpath('./@portid').pop())
						logging.info(f'found cert {issuer_name}/{subject_name} on {host_ip}/{port_num}')

						# start_time
						try:
							start_time = datetime.fromtimestamp(int(host.xpath('./@starttime').pop()))
						except:
							logging.error(f'Failed to grab start time for {host_ip}/{port_num} at ./@starttime', exc_info=True)
							start_time = datetime.min

						# end_time
						try:
							end_time = datetime.fromtimestamp(int(host.xpath('./@endtime').pop()))
						except:
							logging.error(f'Failed to grab end time for {host_ip}/{port_num} at ./@endtime', exc_info=True)
							end_time = datetime.min

						# host_name
						try:
							host_name = host.xpath(host_name_path).pop()
						except:
							logging.error(f'No host name found for {host_ip} at {host_name_path}', exc_info=True)
							host_name = 'NOT FOUND'
						
						# creation_date
						try:
							not_before = p.xpath('.//table[@key="validity"]/elem[@key="notBefore"]/text()').pop()
							creation_date = (try_strptime(not_before)).replace(tzinfo=None)
						except ValueError:
							logging.warning(f'{host_ip} - creation date did not parse correctly into xml\nGiven string: {not_before}')
						except:
							logging.error(f'Failed to grab creation date at .//table[@key="validity"]/elem[@key="notBefore"]/text()', exc_info=True)
							creation_date = (datetime.min).replace(tzinfo=None)

						# expiration_date
						try:
							not_after  = p.xpath('.//table[@key="validity"]/elem[@key="notAfter"]/text()').pop()
							expiration_date = (try_strptime(not_after)).replace(tzinfo=None)
						except ValueError:
							logging.warning(f'{host_ip} - expiration date did not parse correctly into xml\nGiven string: {not_after}')
						except:
							logging.error(f'Failed to grab expiration date at .//table[@key="validity"]/elem[@key="notBefore"]/text()', exc_info=True)
							expiration_date = (datetime.min).replace(tzinfo=None)

						# expires_in
						try:
							days_till_expire = int((expiration_date - datetime.now()).days)
						except:
							logging.error(f'Failed to calculate days until expiration date from expiration date at .//table[@key="validity"]/elem[@key="notBefore"]/text()', exc_info=True)
							days_till_expire = -9000
						
						# creating new cert entry 
						new_cert = Cert(start_time = start_time, end_time=end_time, host_ip=host_ip, host_name=host_name,\
							port_num=port_num, issuer_name=issuer_name, creation_date=creation_date, expiration_date=expiration_date, expires_in=days_till_expire)

						# throw out any duplicated certs
						if new_cert not in list_of_certificates:
							list_of_certificates.append(new_cert)
							logging.info(f'Cert added to list - \n{new_cert}')
						else:
							logging.debug(f'Duplicate entry found, omitting from list {new_cert}')
					else:
                        # this first line seems to need to be blank so every following line has same whitespace for dedent
						logging.debug(dedent(f'''\
											Self-signed certificate found for {host_ip}
											Issuer : {issuer_name}
											Subject: {subject_name}'''))
		# no cert found/added to list_of_certificates, move on to next
		else:
			logging.debug(f'No certificate(s) found on {host_ip}')

	# sort the list of certificates by expiration date
	list_of_certificates.sort(key=lambda x: x.expiration_date)

	return list_of_certificates

def create_cert_entry(list_of_certificates):
	'''
    Populates the database CertModel with certs found in list_of_certificates

		Parameters:
				list_of_certificates (list): sorted list of unique certifications (w/o duplicated values), sorted by expiration date

		Returns:
				N/A
    '''
	for cert in list_of_certificates:

		CertModel.create(start_time = cert.start_time, end_time = cert.end_time, host_ip = cert.host_ip, host_name = cert.host_name,  \
			port_num = cert.port_num, issuer_name = cert.issuer_name, creation_date = cert.creation_date, expiration_date = cert.expiration_date, expires_in = cert.expires_in)

		logging.info(f'Table entry created \n{cert}')		

def send_email(list_of_certificates, expired):
	"""
    Pushes email w/ html table of certifications to specified email address

            Parameters:
					list_of_certificates (list): sorted list of unique certifications (w/o duplicated values), sorted by expiration date

            Returns:
                    N/A
    """

	now = datetime.now()
	one_year = timedelta(days = 365)
	msg = EmailMessage()
	msg['From'] = 'SSL Certificate Scanner <noreply@rowan.edu>'
	msg['To'] = ('graham26@rowan.edu')

	# TODO: add nmap scan info here in email_message_body

	# change subject line and body based on expired/expiring
	if not expired:
		msg['Subject'] = 'Expiring SSL certificates'
		email_message_body = f"""
		<h3>This list includes all discovered certificates that will expire in the next 365 days:</h3>
		"""
	else:
		msg['Subject'] = '[EXPIRED] SSL certificates'
		email_message_body = f"""
		<h3>This list includes all discovered certificates that <u>have expired.</u></h3>
		"""

	# table heading
	email_message_body += """
	<table border="1" width="80%">
		<tr>
			<th>Host Name</th>
			<th>Port #</th>
			<th>Days till Expiration</th>
			<th>Certificate Authority</th>
			<th>Expiration Date</th>
		</tr>
	"""

	for cert in list_of_certificates:
		
		expiration_date = cert.expiration_date
		
		if not expired:
			if now + one_year > expiration_date and expiration_date > now :
				days_till_expire = (expiration_date - now).days
				email_message_body += (f"""
					<tr>
						<td>{cert.host_name}</td>
						<td>{cert.port_num}</td>
						<td>{days_till_expire}</td>
						<td>{cert.issuer_name}</td>
						<td>{cert.expiration_date.date()}</td>
					</tr>
					""")
		else:
			if expiration_date < now:
				days_till_expire = (expiration_date - now).days
				email_message_body += (f"""
					<tr>
						<td>{cert.host_name}</td>
						<td>{cert.port_num}</td>
						<td>{days_till_expire}</td>
						<td>{cert.issuer_name}</td>
						<td>{cert.expiration_date.date()}</td>
					</tr>
					""")

	email_message_body += """
	</table>
	"""

	# Push email
	try:   
		smtp_obj = smtplib.SMTP('mail.rowan.edu', 25)			# port 25 is the smtp port
		msg.set_content(email_message_body, subtype = 'html')
		smtp_obj.send_message(msg)
		logging.debug("Email has been sent.")
	except smtplib.SMTPException:
		logging.error("Failed to send email", exc_info=True)
		print("Email was unable to be sent...")

if __name__ == '__main__': 
	main()

			
			
















