from peewee import *
from textwrap import dedent

# global db
db = MySQLDatabase(database='ssl_check', host = 'db', user = 'root', password = '1234')

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