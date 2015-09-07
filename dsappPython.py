##################################################################################################
#
#	<Python 2.6>
#	dsapp was created to help customers and support engineers troubleshoot
#	and solve common issues for the Novell GroupWise Mobility product.
#
#	Rewritten in python by: Shane Nielson <snielson@novell.com>
#	Original dsapp by: Shane Nielson & Tyler Harris <tharris@novell.com>
#
##################################################################################################

dsappversion='223'

##################################################################################################
#	Imports
##################################################################################################

import os
import sys
import signal
import socket
import logging
import logging.config
import time
import atexit
import re
import tarfile, zipfile
import rpm
import urllib2
ts = rpm.TransactionSet()
import ConfigParser
Config = ConfigParser.ConfigParser()

### Unused imports during dev --- Remove after ###
# import getpass
# import shutil
# import fileinput
# import glob
# import subprocess
# import itertools

# Check for dsapp/logs folder (Needed for logs)
if not os.path.exists('/opt/novell/datasync/tools/dsapp/logs/'):
	os.makedirs('/opt/novell/datasync/tools/dsapp/logs/')

sys.path.append('./lib')
# TODO : uncomment on mobility server
# sys.path.append('/opt/novell/datasync/common/lib/')
sys.path.append('/root/Desktop/scripts/python/lib')
import dsappDefinitions as ds
import spin
import psycopg2

##################################################################################################
#	Start up check
##################################################################################################

# Make sure user is root
if (os.getuid() != 0):
	print ("Please login as root to run this script")
	sys.exit(1)

##################################################################################################
#	Global Variables
##################################################################################################

# Start up variables
forceMode = False
installedConnector = "/etc/init.d/datasync-connectors"
isInstalled = False

# Folder variables
dsappDirectory = "/opt/novell/datasync/tools/dsapp"
dsappConf = dsappDirectory + "/conf"
dsappLogs = dsappDirectory + "/logs"
dsapplib = dsappDirectory + "/lib"
dsappBackup = dsappDirectory + "/backup"
dsapptmp = dsappDirectory + "/tmp"
dsappupload = dsappDirectory + "/upload"
rootDownloads = "/root/Downloads"

# Configuration Files
# mconf = "/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml"
# gconf = "/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/groupwise/connector.xml"
# ceconf = "/etc/datasync/configengine/configengine.xml"
econf = "/etc/datasync/configengine/engines/default/engine.xml"
# wconf = "/etc/datasync/webadmin/server.xml"

# Test server paths
mconf = "/root/Desktop/confXML/mobility/connector.xml"
gconf = "/root/Desktop/confXML/groupwise/connector.xml"
ceconf = "/root/Desktop/confXML/configengine.xml"
wconf = "/root/Desktop/confXML/server.xml"

# Misc variables
serverinfo = "/etc/*release"
rpminfo = "datasync"
dsapp_tar = "dsapp.tgz"
isNum = '^[0-9]+$'
ds_20x = '2000'
ds_21x = '2100'
previousVersion = "20153"
latestVersion = "210230"
mobilityVersion = "0"
version = "/opt/novell/datasync/version"

# Mobility Directories
dirOptMobility = "/opt/novell/datasync"
dirEtcMobility = "/etc/datasync"
dirVarMobility = "/var/lib/datasync"
log = "/var/log/datasync"
dirPGSQL = "/var/lib/pgsql"
mAttach = dirVarMobility + "/mobility/attachments/"

# Mobility logs
configenginelog = log + "/configengine/configengine.log"
connectormanagerlog = log + "/syncengine/connectorManager.log"
syncenginelog = log + "/syncengine/engine.log"
monitorlog = log + "/monitorengine/monitor.log"
systemagentlog = log + "/monitorengine/systemagent.log"
updatelog = log + "/update.log"
webadminlog = log + "/webadmin/server.log"

# System logs
messages = "/var/log/messages"
warn = "/var/log/warn"

# dsapp Conf / Logs
dsappSettings = dsappConf + "/setting.cfg"
dsappLogSettings = dsappConf + "/logging.cfg"
dsappLog = dsappConf + "/dsapp.log"
ghcLog = dsappConf + "/generalHealthCheck.log"

##################################################################################################
#	Log Settings
##################################################################################################

# if os.path.isfile(dsappLogSettings):
# 	Config.read(dsappLogSettings)
# print Config.get('logger___main__', 'level')

# TODO: Change logger level via switch
logging.config.fileConfig(dsappLogSettings)
logger = logging.getLogger(__name__)
logger.info('------------- Starting dsapp -------------')

##################################################################################################
#	Setup local definitions
##################################################################################################

# Define Variables for Eenou+ (2.x)
def declareVariables2():
	mAlog = log + "/connectors/mobility-agent.log"
	gAlog = log + "/connectors/groupwise-agent.log"
	mlog = log + "/connectors/mobility.log"
	glog = log + "/connectors/groupwise.log"
	# TODO: rcScript = "rcgms"

# Define Variables for Pre-Eenou (1.x)
def declareVariables1():
	mAlog = log + "/connectors/default.pipeline1.mobility-AppInterface.log"
	gAlog = log + "/connectors/default.pipeline1.groupwise-AppInterface.log"
	mlog = log + "/connectors/default.pipeline1.mobility.log"
	glog = log + "/connectors/default.pipeline1.groupwise.log"
	# TODO: rcScript="rcdatasync"

def exit_cleanup():
	try:
		if spinner.isAlive():
			spinner.stop()
	except NameError:
		pass

	# Clear dsapp/tmp
	ds.removeAllFiles("/opt/novell/datasync/tools/dsapp/tmp/")

	# Removes .pgpass if pgpass=true in dsapp.conf
	if pgpass:
		if sum(1 for line in open(dsappConf + '/dsapp.pid')) == 1:
			try:
				os.remove('/root/.pgpass')
			except OSError:
				ds.logger.warning('No such file or directory: /root/.pgpass')

	# Remove PID from dsapp.pid
	ds.removeLine(dsappConf + '/dsapp.pid', str(os.getpid()))


def signal_handler_SIGINT(signal, frame):
	monitorValue = False # TEMP

	# Exit watch while staying in dsapp
	if monitorValue:
		monitorValue = False
	else:
		# Clean up dsapp
		exit_cleanup
		# Reset the terminal
		sys.exit(1)

def set_spinner():
	spinner = spin.progress_bar_loading()
	spinner.setDaemon(True)
	return spinner

def announceNewFeature():
	if newFeature:
		ds.datasyncBanner(dsappversion)
		ds.logger.debug('Prompt feature')
		print "General Health Check.\nLocated in the Checks & Queries menu.\n"
		if ds.askYesOrNo("Would you like to run it now?"):
			pass
			# TODO: generalHealthCheck()

	with open(dsappSettings, 'w') as cfgfile:
		Config.set('Misc', 'new.feature', False)
		Config.write(cfgfile)

def updateDsapp(publicVersion):
	print 'Updating dsapp to v%s' % (publicVersion)
	ds.logger.info('Updating dsapp to v%s' % (publicVersion))

	# Download new version & extract
	# TODO : Test if service exists
	ds.dlfile('ftp://ftp.novell.com/outgoing/%s' % (dsapp_tar))
	print
	tar = tarfile.open(dsapp_tar, 'r:gz')
	rpmFile = re.search('.*.rpm' ,'%s' % (tar.getnames()[0])).group(0)
	tar.close()
	ds.uncompressIt(dsapp_tar)
	if ds.checkRPM(rpmFile):
		ds.setupRPM(rpmFile)
	else:
		print ('%s is older than installed version' % (rpmFile))
		ds.logger.warning('%s is older than installed version' % (rpmFile))

	# Clean up files
	try:
		os.remove('dsapp.sh')
	except OSError:
		ds.logger.warning('No such file: dsapp.sh')
	try:
		os.remove(rpmFile)
	except OSError:
		ds.logger.warning('No such file: %s' % (rpmFile))
	try:
		os.remove(dsapp_tar)
	except OSError:
		ds.logger.warning('No such file: %s' % (dsapp_tar))
	# TODO: Close script, and relaunch

def autoUpdateDsapp():
	# Variable declared above autoUpdate=true
	if autoUpdate:
		# Check FTP connectivity
		if ds.DoesServiceExist('ftp.novell.com', 21):
			# Fetch online dsapp and store to memory, check version
			spinner = set_spinner()
			ds.logger.info('Checking for a newer version of dsapp')
			print 'Checking for a newer version of dsapp... ',
			spinner.start(); time.sleep(.000001)
			for line in urllib2.urlopen('ftp://ftp.novell.com/outgoing/dsapp-version.info'):
				publicVersion = line.split("'")[1]
			spinner.stop(); print
			ds.clear()
			
			# Download if newer version is available
			if dsappversion < publicVersion and publicVersion is not None:
				print 'v%s (v%s available)' % (dsappversion, publicVersion)
				ds.logger.info('Updating dsapp v%s to v%s' % (dsappversion, publicVersion))
				updateDsapp(publicVersion)
			elif dsappversion >= publicVersion and publicVersion is not None:
				ds.logger.info('dsapp is up-to-date at')

def getDSVersion():
	if isInstalled:
		with open(version) as f:
			value = f.read().translate(None, '.')[0:4]
		return value

def checkPostgresql():
	# TODO: Finish this code
	try:
		conn = psycopg2.connect("dbname='datasync' user='%s' host='localhost' password='novell'" % (dbUsername))
	except:
		print "I am unable to connect to the database"

	# cur = conn.cursor()
	# cur.execute("""SELECT dn from targets""")
	# for row in rows:
	# 	print "   ", row[0]



##################################################################################################
#	Set up script
##################################################################################################

# Register exit_cleanup with atexit
atexit.register(exit_cleanup)

# SIG trap dsapp
signal.signal(signal.SIGINT, signal_handler_SIGINT)

# Create dsapp folder stucture
dsapp_folders = [dsappDirectory, dsappConf, dsappLogs, dsappBackup, dsapptmp, dsappupload, rootDownloads, dsapplib]
for folder in dsapp_folders:
	if not os.path.exists(folder):
		os.makedirs(folder)

# Get dsapp PID
with open(dsappConf + '/dsapp.pid', 'w') as pidFile:
	pidFile.write(str(os.getpid()) + '\n')
	
# Clean up previous PIDs if not found
with open(dsappConf + '/dsapp.pid', 'r') as pidFile:
	for line in pidFile:
		if not ds.check_pid(int(line)):
			ds.removeLine(dsappConf + '/dsapp.pid', line)

# Get Hostname of server, and store in setting.cfg
try:
	if not os.path.isfile(dsappSettings):
		with open('/etc/HOSTNAME', 'r') as f:
			dsHostname = f.read().strip()
except IOError:
	pass
	logger.warning('Unable to get hostname of server')
	# TODO: Set flag to skip any hostname check in dsapp

# Create setting.cfg if not found
if not os.path.isfile(dsappSettings):
	with open(dsappSettings, 'w') as cfgfile:
		Config.add_section('Misc')
		Config.add_section('Settings')
		Config.set('Settings', 'pgpass', True)
		Config.set('Misc', 'hostname', dsHostname)
		Config.set('Settings', 'new.feature', False)
		Config.set('Misc', 'dsapp.version', dsappversion)
		Config.set('Settings', 'auto.update', True)
		Config.write(cfgfile)

# Assign variables based on settings.cfg
Config.read(dsappSettings)
pgpass = Config.getboolean('Settings', 'pgpass')
dsHostname = Config.get('Misc', 'hostname')
newFeature = Config.getboolean('Settings', 'new.feature')
autoUpdate = Config.getboolean('Settings', 'auto.update')

# Get Console Size
windowSize = rows, columns = os.popen('stty size', 'r').read().split()
if int(windowSize[0]) < int(24) or int(windowSize[1]) < int(80):
	print ("Terminal window does not meet size requirements\nCurrent Size: [%s x %s]\nPlease resize window to [80 x 24] or greater\n" % (windowSize[1],windowSize[0]))
	sys.exit(1)

# Switch Array for valid switches
switchArray=('-h', '--help', '--version', '--debug', '--bug', '-au', '--autoUpdate', '-ghc', '--gHealthCheck', '-f', '--force', '-ul', '--uploadLogs', '-c', '--check', '-s', '--status', '-up', '--update', '-v', '--vacuum', '-i', '--index', '-u', '--users', '-d', '--devices', '-db', '--database', '-ch', '--changeHost', '-re', '--restore', '--updateDsapp')

# Verify all passed in switches used are valid
switchCheck = sys.argv
del switchCheck[0]
switchError = False
for switch in switchCheck:
	if switch not in switchArray:
		print ("dsapp: %s is not a valid command. See '--help'." % (switch))
		switchError = True

# Exit script if invalid switch found
if switchError:
	sys.exit(1)

# Check and set force to True
forceArray = ('--force', '-f', '?', '-h', '--help', '-db', '--database', '-re', '--restore')
for switch in switchCheck:
	if switch in forceArray:
		forceMode = True

# Give force mode warning
if forceMode:
	if '-f' in switchCheck or '--force' in switchCheck:
		ds.datasyncBanner(dsappversion)
		print ("Running force mode. Some options may not work properly.\n")
		logger.warning('Running in force mode')
		ds.eContinue()

# Check if Mobility is installed on the server
isInstalled = ds.checkInstall(forceMode, installedConnector)

# Get Mobility Version
mobilityVersion = ds.getVersion(isInstalled, version)

# Get current working directory
cPWD = os.getcwd()

# Get mobility version
dsVersion = getDSVersion()

##################################################################################################
#	Initialization
##################################################################################################

# Load Menu (Get all needed variables)
if len(sys.argv) == 0:
	ds.datasyncBanner(dsappversion)

	# Read values from XML config
	if isInstalled:
		print "Loading settings... ",
		# Start spinner
		spinner = set_spinner()
		spinner.start(); time.sleep(.000001)
		# XML tree of each XML file
		logger.info('Building XML trees started')
		time1 = time.time()
		logger.debug('Building %s tree from: %s' % ('mconfXML', mconf))
		mconfXML = ds.getXMLTree(mconf)
		logger.debug('Building %s tree from: %s' % ('ceconfXML', ceconf))
		ceconfXML = ds.getXMLTree(ceconf)
		logger.debug('Building %s tree from: %s' % ('wconfXML', wconf))
		wconfXML = ds.getXMLTree(wconf)
		logger.debug('Building %s tree from: %s' % ('gconfXML', gconf))
		gconfXML = ds.getXMLTree(gconf)
		time2 = time.time()
		logger.info('Building XML trees complete')
		logger.debug("Building XML trees took %0.3f ms" % ((time2 - time1) * 1000))

		time1 = time.time()
		logger.info('Assigning variables from XML started')
		logger.debug('Assigning %s from %s' % ('ldapSecure', 'ceconfXML'))
		ldapSecure = ds.xmlpath('.//configengine/ldap/secure', ceconfXML)
		logger.debug('Assigning %s from %s' % ('ldapAdmin', 'ceconfXML'))
		ldapAdmin = ds.xmlpath('.//configengine/ldap/login/dn', ceconfXML)
		logger.debug('Assigning %s from %s' % ('provisioning', 'ceconfXML'))
		provisioning = ds.xmlpath('.//configengine/source/provisioning', ceconfXML)
		logger.debug('Assigning %s from %s' % ('authentication', 'ceconfXML'))
		authentication = ds.xmlpath('.//configengine/source/authentication', ceconfXML)
		logger.debug('Assigning %s from %s' % ('ldapEnabled', 'ceconfXML'))
		ldapEnabled = ds.xmlpath('.//configengine/ldap/enabled', ceconfXML)
		logger.debug('Assigning %s from %s' % ('groupContainer', 'ceconfXML'))
		groupContainer = ds.xmlpath('.//configengine/ldap/groupContainer', ceconfXML)
		logger.debug('Assigning %s from %s' % ('userContainer', 'ceconfXML'))
		userContainer = ds.xmlpath('.//configengine/ldap/userContainer', ceconfXML)
		logger.debug('Assigning %s from %s' % ('webAdmins', 'ceconfXML'))
		webAdmins = ds.xmlpath('.//configengine/ldap/admins/dn', ceconfXML)
		logger.debug('Assigning %s from %s' % ('dbUsername', 'ceconfXML'))
		dbUsername = ds.xmlpath('.//configengine/database/username', ceconfXML)

		logger.debug('Assigning %s from %s' % ('ldapAddress', 'mconfXML'))
		ldapAddress = ds.xmlpath('.//settings/custom/ldapAddress', mconfXML)
		logger.debug('Assigning %s from %s' % ('ldapPort', 'mconfXML'))
		ldapPort = ds.xmlpath('.//settings/custom/ldapPort', mconfXML)
		logger.debug('Assigning %s from %s' % ('mPort', 'mconfXML'))
		mPort = ds.xmlpath('.//settings/custom/listenPort', mconfXML)
		logger.debug('Assigning %s from %s' % ('mSecure', 'mconfXML'))
		mSecure = ds.xmlpath('.//settings/custom/ssl', mconfXML)
		logger.debug('Assigning %s from %s' % ('mlistenAddress', 'mconfXML'))
		mlistenAddress = ds.xmlpath('.//settings/custom/listenAddress', mconfXML)
		logger.debug('Assigning %s from %s' % ('galUserName', 'mconfXML'))
		galUserName = ds.xmlpath('.//settings/custom/galUserName', mconfXML)
		logger.debug('Assigning %s from %s' % ('mAttachSize', 'mconfXML'))
		mAttachSize = ds.xmlpath('.//settings/custom/attachmentMaxSize', mconfXML)

		logger.debug('Assigning %s from %s' % ('sListenAddress', 'gconfXML'))
		sListenAddress = ds.xmlpath('.//settings/custom/listeningLocation', gconfXML)
		logger.debug('Assigning %s from %s' % ('trustedName', 'gconfXML'))
		trustedName = ds.xmlpath('.//settings/custom/trustedAppName', gconfXML)
		logger.debug('Assigning %s from %s' % ('gPort', 'gconfXML'))
		gPort = ds.xmlpath('.//settings/custom/port', gconfXML)
		logger.debug('Assigning %s from %s' % ('gAttachSize', 'gconfXML'))
		gAttachSize = ds.xmlpath('.//settings/custom/attachmentMaxSize', gconfXML)
		logger.debug('Assigning %s from %s' % ('gListenAddress', 'gconfXML'))
		gListenAddress = ds.xmlpath('.//settings/custom/soapServer', gconfXML).split("://",1)[1].split(":",1)[0]
		logger.debug('Assigning %s from %s' % ('sPort', 'gconfXML'))
		sPort = ds.xmlpath('.//settings/custom/soapServer', gconfXML).split("://",1)[1].split(":",1)[1].split("/",1)[0]
		logger.debug('Assigning %s from %s' % ('sSecure', 'gconfXML'))
		sSecure = ds.xmlpath('.//settings/custom/soapServer', gconfXML).split("://",1)[0]

		logger.debug('Assigning %s from %s' % ('wPort', 'wconfXML'))
		wPort = ds.xmlpath('.//server/port', wconfXML)
		time2 = time.time()
		logger.info('Assigning variables from XML complete')
		logger.debug("Assigning variables took %0.3f ms" % ((time2 - time1) * 1000))
		# Stop spinner
		spinner.stop(); print '\n'

else:
	ds.clear()

##################################################################################################
#	Main
##################################################################################################

# TEST CODE / Definitions

ds.datasyncBanner(dsappversion)

# autoUpdateDsapp()

ds.eContinue()
sys.exit(0)
