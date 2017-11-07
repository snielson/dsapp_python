#!/usr/bin/env python
# Written by Shane Nielson <snielson@projectuminfinitas.com>

from __future__ import print_function

__author__ = "Shane Nielson"
__maintainer__ = "Shane Nielson"

import os
import sys
import logging, logging.config
import ast
import dsapp_Definitions as ds
import re
import gzip
import datetime
import contextlib
import spin
import time
import sqlite3
import imp
pydoc = imp.load_source('pydoc', os.path.dirname(os.path.realpath(__file__)) + '/pydoc.py')
import tempfile
import subprocess

# Global variables
import dsapp_global as glb
environ_db = glb.dsapptmp + '/environ.sqlite'

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (glb.dsappConf))
logger = logging.getLogger('dsapp_Definitions')
excep_logger = logging.getLogger('exceptions_log')
perform_logger = logging.getLogger('performance_log')

def my_handler(type, value, tb):
	tmp = traceback.format_exception(type, value, tb)
	logger.error("EXCEPTION: See exception.log")
	excep_logger.error("Uncaught exception:\n%s" % ''.join(tmp).strip())
	print (''.join(tmp).strip())

def set_spinner():
	spinner = spin.progress_bar_loading()
	spinner.setDaemon(True)
	return spinner

# Parse logs, and build a list of dictionaries
def getEnvrion(log=None):
	# Regex to find the problem object values
	regex = re.compile(r"(<[^\z]+>)|(<[^>]+>)")

	if log is None:
		# Set the variables to the correct logs
		ds.setVariables()
		log = glb.mAlog

	# Get log size
	logMB = os.path.getsize(log)/1024.0/1024.0

	spinner = set_spinner()
	print ("\nParsing %0.2fMB log.. " % logMB, end='')
	spinner.start(); time.sleep(.000001)
	time1 = time.time()
	logger.info("Parsing %0.2fMB log: %s" % (logMB, log))
	perform_logger.info("Parsing %0.2fMB log: %s" % (logMB, log))

	# If db already exists. remove it
	if os.path.isfile(environ_db):
		os.remove(environ_db)

	# Create a sqlite db to store the values
	conn = sqlite3.connect(environ_db)
	cur = conn.cursor()
	cur.execute("CREATE TABLE environ(REMOTE_ADDR TEXT, QUERY_STRING TEXT, HTTP_HOST TEXT, SERVER_PORT TEXT)")
	conn.commit()
	conn_flush = 0

	extension = ds.getFileExtension(log)
	if extension == '.log':
		with open(log, 'r') as inf:
			for line in inf:
				if '[Server] environ' in line:
					tempLine = line.strip()
					environ_dict = ("{%s}\n" % tempLine.split('{')[1].split('}')[0])
					if environ_dict is not None:
						newLine = regex.sub("'*****'", environ_dict)
						try:
							temp_dict = [ast.literal_eval(newLine)]
						except:
							perform_logger.warning("Syntax Error!\n%s" % newLine)

						try:
							cur.execute("INSERT into environ values (?,?,?,?)", [temp_dict[0]['REMOTE_ADDR'], temp_dict[0]['QUERY_STRING'], temp_dict[0]['HTTP_HOST'], temp_dict[0]['SERVER_PORT']])
							conn_flush += 1
						except:
							perform_logger.warning("INSERT Error!\n%s" % temp_dict[0])

					if conn_flush >= 500:
						conn.commit()
						conn_flush = 0

	# Add support for .gz files
	elif extension == '.gz':
		with contextlib.closing(gzip.open(log, 'r')) as inf:
			for line in inf:
				if '[Server] environ' in line:
					tempLine = line.strip()
					environ_dict = ("{%s}\n" % tempLine.split('{')[1].split('}')[0])
					if environ_dict is not None:
						newLine = regex.sub("'*****'", environ_dict)
						try:
							temp_dict = [ast.literal_eval(newLine)]
						except:
							perform_logger.warning("Syntax Error!\n%s" % newLine)

						try:
							cur.execute("INSERT into environ values (?,?,?,?)", [temp_dict[0]['REMOTE_ADDR'], temp_dict[0]['QUERY_STRING'], temp_dict[0]['HTTP_HOST'], temp_dict[0]['SERVER_PORT']])
							conn_flush += 1
						except:
							perform_logger.warning("INSERT Error!\n%s" % temp_dict[0])

					if conn_flush >= 500:
						conn.commit()
						conn_flush = 0

	# Commit any final changes, and close sqlite connections
	conn.commit()
	cur.close()
	conn.close()

	# Stop spinner
	spinner.stop(); print ('\n')
	time2 = time.time()
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	perform_logger.info("Operation took %0.3f ms\n" % ((time2 - time1) * 1000))


# Create dictionary of users, devices, cmd, and counts
def create_QueryString_table(log=None):
	getEnvrion(log)

	conn = sqlite3.connect(environ_db)
	cur = conn.cursor()

	# Check if environ table is empty
	cur.execute("SELECT count(*) from environ")
	data = cur.fetchall()
	if data[0][0] == 0:
		print ("No data found\nCheck log or log level")
		logger.info("No data found")
		cur.close()
		conn.close()
		print()
		return False

	cur.execute("CREATE TABLE data(user TEXT, userKey TEXT, cmd TEXT, deviceid TEXT, devicetype TEXT, address TEXT)")
	conn.commit()

	spinner = set_spinner()
	print ("Creating table.. ", end='')
	spinner.start(); time.sleep(.000001)
	time1 = time.time()
	logger.info("Creating table: %s" % log)
	perform_logger.info("Creating table: %s" % log)

	cur.execute("SELECT QUERY_STRING, REMOTE_ADDR from environ")
	data = cur.fetchall()

	conn_flush = 0
	for row in data:

		# Get user
 		try:
 			user = row[0].split('User=')[1].split('&')[0]
 		except:
 			user = None

 		# Get cmd
 		try:
 			cmd = row[0].split('Cmd=')[1].split('&')[0]
 		except:
 			cmd = None

 		# Get deviceid
 		try:
 			deviceId = row[0].split('DeviceId=')[1].split('&')[0]
 		except:
 			deviceId = None
 		
 		# Get deviceType
 		try:	
 			deviceType = row[0].split('DeviceType=')[1].split("'")[0]
 		except:
 			deviceType = None

 		# Get address
 		try:	
 			remoteAddr = row[1]
 		except:
 			remoteAddr = None

 		userKey = "%s:%s" % (user, deviceId)

 		cur.execute("INSERT into data values (?,?,?,?,?,?)", [user, userKey, cmd, deviceId, deviceType, remoteAddr])
 		conn_flush += 1
 		if conn_flush >= 500:
			conn.commit()
			conn_flush = 0

	conn.commit()
	cur.close()
	conn.close()

	# Stop spinner
	spinner.stop(); print ('\n')
	time2 = time.time()
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	perform_logger.info("Operation took %0.3f ms\n" % ((time2 - time1) * 1000))
	return True

def getDeviceCommands(log):
	if create_QueryString_table(log):

		# Create tempfile for large tables
		with tempfile.TemporaryFile(mode='w+b') as name:
			select_cmd = "sqlite3 -column -header %s 'select user as \"User\", deviceid as \"DeviceId\", address as \"Address\", cmd as \"Command\", count(cmd) as \"Count\" from data group by userKey, cmd order by \"Count\" desc;'" % environ_db
			p = subprocess.Popen(select_cmd, shell=True, stdout=name)
			p.wait()
			name.seek(0)
			out = name.read()
			pydoc.pager(out)

		if ds.askYesOrNo("Output results to CSV"):
			DATE = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
			select_cmd = "sqlite3 -csv -header %s 'select user as \"User\", deviceid as \"DeviceId\", address as \"Address\", cmd as \"Command\", count(cmd) as \"Count\" from data group by userKey, cmd order by \"Count\" desc;' > %s/device_requests-%s.csv" % (environ_db, glb.dsappdata, DATE)
			out = ds.util_subprocess(select_cmd)
			print ("Data exported to %s/device_requests-%s.csv" % glb.dsappdata, DATE)
		print()
	

def getPinglessDevices(log):
	if create_QueryString_table(log):

		# Create tempfile for large tables
		with tempfile.TemporaryFile(mode='w+b') as name:
			select_cmd ="sqlite3 -column -header %s 'select user as \"User\", deviceid as \"DeviceId\", address as \"Address\" from data where deviceid not in (select deviceid from data where cmd=\"Ping\") group by deviceid;'" % environ_db
			p = subprocess.Popen(select_cmd, shell=True, stdout=name)
			p.wait()
			name.seek(0)
			out = name.read()
			pydoc.pager(out)

		if ds.askYesOrNo("Output results to CSV"):
			DATE = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
			select_cmd ="sqlite3 -csv -header %s 'select user as \"User\", deviceid as \"DeviceId\", address as \"Address\" from data where deviceid not in (select deviceid from data where cmd=\"Ping\") group by deviceid;' > %s/manualSync_devices-%s.csv" % (environ_db, glb.dsappdata, DATE)
			out = ds.util_subprocess(select_cmd)
			print ("Data exported to %s/manualSync_devices-%s.csv" % glb.dsappdata, DATE)
		print()
