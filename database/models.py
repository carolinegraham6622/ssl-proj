import yaml
from peewee import *
from sqlalchemy.orm import declarative_base
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, DateTime, insert

# For a MySQL database -> user:password@host/dbname
with open("./database/database-config.yml", encoding="utf-8") as f:
    config = yaml.safe_load(f)

meta = MetaData()
user = config["user"]
pw = config["pw"]
host = config["host"]
dbname = config["ssl_certificates"]
engine = create_engine(
	f"mysql://{user}:{pw}@{host}/{dbname}",
	echo = True,
	future=True)

Base = declarative_base()

certificates = Table(
    'certificates',
    meta,
    Column('host_ip', String(length=50), primary_key=True),
    Column('start_time', DateTime),
	Column('end_time', DateTime),
	Column('host_name', String(length=50)),
	Column('port_num',Integer),
	Column('issuer_name', String(length=50)),
	Column('creation_date', DateTime),
	Column('expiration_date', DateTime), 
	Column('expires_in', IntegerField)
)

try:
	meta.create_all(engine)
except:
	print('Database could not be connected to.')

class Certificate(Base):
	__table__ = certificates

	def create_certificate(certificate):
		'''
		Creates a new row in the database
		'''

		# sqlalchemy insert statement 
		stmt = insert(certificate).values(
			# TODO: add the necessary fields here
			# ex: user_id = user['id'],
			host_ip = certificate['host_ip']
		)

		with engine.connect() as conn:
			result = conn.execute(stmt)
			print(f'Results: {result}')
			conn.commit()
