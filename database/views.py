from peewee import *

from database.models import Table as myTable

def database_connect():

    db = MySQLDatabase("ssl_certificates",host = 'db', user = 'root', password = '1234')
    db.create_tables([myTable])

    pass
