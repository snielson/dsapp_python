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

# Folder variables
dsappDirectory = "/opt/novell/datasync/tools/dsapp"
dsappConf = dsappDirectory + "/conf"
dsappLogs = dsappDirectory + "/logs"
dsapplib = dsappDirectory + "/lib"
dsappBackup = dsappDirectory + "/backup"
dsapptmp = dsappDirectory + "/tmp"
dsappupload = dsappDirectory + "/upload"
dsappdata = dsappDirectory + "/data"
rootDownloads = "/root/Downloads"

# Misc variables
ds_1x= 1
ds_2x = 2
ds_14x = 14
mobilityVersion = 0
version = "/opt/novell/datasync/version"

# Mobility Directories variables
dirOptMobility = "/opt/novell/datasync"
dirEtcMobility = "/etc/datasync"
dirVarMobility = "/var/lib/datasync"
log = "/var/log/datasync"
dirPGSQL = "/var/lib/pgsql"
mAttach = dirVarMobility + "/mobility/attachments/"

# Mobility logs variables
configenginelog = log + "/configengine/configengine.log"
connectormanagerlog = log + "/syncengine/connectorManager.log"
syncenginelog = log + "/syncengine/engine.log"
monitorlog = log + "/monitorengine/monitor.log"
systemagentlog = log + "/monitorengine/systemagent.log"
updatelog = log + "/update.log"
webadminlog = log + "/webadmin/server.log"
mAlog = None
gAlog = None
mlog = None
glog = None
sudslog = log + "/connectors/suds.log"

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (dsappConf))
logger = logging.getLogger('dsapp_Definitions')
excep_logger = logging.getLogger('exceptions_log')

def my_handler(type, value, tb):
	tmp = traceback.format_exception(type, value, tb)
	logger.error("EXCEPTION: See exception.log")
	excep_logger.error("Uncaught exception:\n%s" % ''.join(tmp).strip())
	print (''.join(tmp).strip())

# Define Variables for Eenou+ (2.x)
def declareVariables2():
	global mAlog
	global gAlog
	global mlog
	global glog

	logger.debug('Setting version variables for 2.X')
	mAlog = log + "/connectors/mobility-agent.log"
	gAlog = log + "/connectors/groupwise-agent.log"
	mlog = log + "/connectors/mobility.log"
	glog = log + "/connectors/groupwise.log"

# Define Variables for Pre-Eenou (1.x)
def declareVariables1():
	global mAlog
	global gAlog
	global mlog
	global glog

	logger.debug('Setting version variables for 1.X')
	mAlog = log + "/connectors/default.pipeline1.mobility-AppInterface.log"
	gAlog = log + "/connectors/default.pipeline1.groupwise-AppInterface.log"
	mlog = log + "/connectors/default.pipeline1.mobility.log"
	glog = log + "/connectors/default.pipeline1.groupwise.log"

def getDSVersion():
	with open(version) as f:
		value = f.read().split('.')[0]
			
	return int(value)

def setVariables():
	dsVersion = getDSVersion()
	# Depends on version 1.x or 2.x
	if dsVersion >= ds_1x:
		declareVariables2()
	else:
		declareVariables1()

# Parse logs, and build a list of dictionaries
def getEnvrion():
	# Regex to find the problem object values
	regex = re.compile(r"(<[^\z]+>)|(<[^>]+>)")

	# Set the variables to the correct logs
	setVariables()

	# Createa a list of dictionaries based on logs
	dict_from_file = []
	with open(mAlog, 'r') as inf:
		for line in inf:
			if 'environ' in line:
				tempLine = line.strip()
				environ_dict = ("{%s}\n" % tempLine.split('{')[1].split('}')[0])
				if environ_dict is not None:
					newLine = regex.sub("'*****'", environ_dict)
					# print (newLine)
					dict_from_file.append(ast.literal_eval(newLine))


	return dict_from_file

# Create dictionary of users, devices, cmd, and counts
def countUsers():
	counts = dict()
	counts['Users'] = dict()

	environ_list = getEnvrion()
	for item in environ_list:

		# Get user
		try:
			user = item['QUERY_STRING'].split('User=')[1].split('&')[0]
		except:
			user = None

		try:
			cmd = item['QUERY_STRING'].split('Cmd=')[1].split('&')[0]
		except:
			cmd = None

		try:
			deviceId = item['QUERY_STRING'].split('DeviceId=')[1].split('&')[0]
		except:
			deviceId = None

		try:	
			deviceType = item['QUERY_STRING'].split('DeviceType=')[1].split("'")[0]
		except:
			deviceType = None

		# Create dictionary based on user with count
		if user in counts['Users']:
			counts['Users'][user]['Total_Count'] += 1
		else:
			counts['Users'][user] = dict()
			counts['Users'][user]['Command'] = dict()
			counts['Users'][user]["DeviceId"] = dict()
			counts['Users'][user]["DeviceType"] = dict()
			counts['Users'][user]['Total_Count'] = 1

		# Count cmd based on user
		if cmd in counts['Users'][user]['Command']:
			counts['Users'][user]['Command'][cmd] += 1
		else:
			counts['Users'][user]['Command'][cmd] = 1

		# Count deviceId based on user
		if deviceId in counts['Users'][user]['DeviceId']:
			counts['Users'][user]['DeviceId'][deviceId] += 1
		else:
			counts['Users'][user]['DeviceId'][deviceId] = 1

		# Count deviceType based on user
		if deviceType in counts['Users'][user]['DeviceType']:
			counts['Users'][user]['DeviceType'][deviceType] += 1
		else:
			counts['Users'][user]['DeviceType'][deviceType] = 1

	return counts


