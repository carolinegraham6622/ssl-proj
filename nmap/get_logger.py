import os
import gzip
import logging
from logging.handlers import TimedRotatingFileHandler

def setup_logger(path, name):
	'''
	Takes a path name to save the logs to, and a name to give the logger.
	Logger can then be retrieved in any module by calling getLogger with the logger name
	once it has been set up. For example, I run logger = setup_logger('./foo.log', 'foo_logger') 
	in main. Then in another module all I need to do is logger = getLogger('foo_logger') and
	any calls like logger.debug('bar') will write to the path specified when the logger was created.
	No need to pass a logger object around to every method that needs it.
	'''
	logger = logging.getLogger(name)
	logger.setLevel(logging.DEBUG)

	#set rotator to gzip files
	def namer(name):
		return name + ".gz"
	def rotator(source, dest):
		with open(source, "rb") as f_in:
			with gzip.open(dest, "wb") as f_out:
				f_out.writelines(f_in)
		os.remove(source)

	ch = TimedRotatingFileHandler(
		path, when='midnight', interval=1, backupCount=3650)
	ch.setLevel(logging.DEBUG)
	ch.rotator = rotator
	ch.namer = namer
	
	# create formatter
	formatter = logging.Formatter(
		'%(asctime)s - %(levelname)s - %(filename)s - '
		'%(lineno)d - %(funcName)s - %(message)s')

	# add formatter to ch
	ch.setFormatter(formatter)

	# add ch to logger
	logger.addHandler(ch)
	return logger
