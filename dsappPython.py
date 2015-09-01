##################################################################################################
#
#	<Python>
#	dsapp was created to help customers and support engineers troubleshoot
#	and solve common issues for the Novell GroupWise Mobility product.
#
#	by Shane Nielson & Tyler Harris
#
##################################################################################################

dsappversion='221'

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

# Unused imports during dev
# import getpass
# import shutil
# import fileinput
# import glob
# import subprocess

sys.path.append('./lib')
import dsappDefinitions as ds

##################################################################################################
#	Start up check
##################################################################################################

# Make sure user is root
if (os.getuid() != 0):
	sys.exit("Please login as root to run this script")

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
mconf = "/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml"
gconf = "/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/groupwise/connector.xml"
ceconf = "/etc/datasync/configengine/configengine.xml"
econf = "/etc/datasync/configengine/engines/default/engine.xml"
wconf = "/etc/datasync/webadmin/server.xml"

# Test server paths
# mconf = "/root/Desktop/confXML/mobility/connector.xml"
# gconf = "/root/Desktop/confXML/groupwise/connector.xml"
# ceconf = "/root/Desktop/confXML/configengine.xml"
# wconf = "/root/Desktop/confXML/server.xml"

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
dsappconfFile = dsappConf + "/dsapp.conf"
dsappLog = dsappConf + "/dsapp.log"
ghcLog = dsappConf + "/generalHealthCheck.log"

# TODO:
# source "$dsappconfFile"

##################################################################################################
#	Log Settings
##################################################################################################

# TODO: Change logger level via switch
logging.config.fileConfig('./conf/logging.conf')
logger = logging.getLogger(__name__)

logger.info('Start logging')
logger.debug('debug logging')
##################################################################################################
#	Setup local definitions
##################################################################################################

# Define Variables for Eenou+ (2.x)
def declareVariables2():
	mAlog = log + "/connectors/mobility-agent.log"
	gAlog = log + "/connectors/groupwise-agent.log"
	mlog = log + "/connectors/mobility.log"
	glog = log + "/connectors/groupwise.log"
	# rcScript = "rcgms"

# Define Variables for Pre-Eenou (1.x)
def declareVariables1():
	mAlog = log + "/connectors/default.pipeline1.mobility-AppInterface.log"
	gAlog = log + "/connectors/default.pipeline1.groupwise-AppInterface.log"
	mlog = log + "/connectors/default.pipeline1.mobility.log"
	glog = log + "/connectors/default.pipeline1.groupwise.log"
	# rcScript="rcdatasync"

def signal_handler(signal, frame):
	# TODO: Uncomment once pgpass & monitorValue are assigned.
	# global monitorValue
	# global pgpass

  # TEMP
	monitorValue = False
	pgpass = False

	# Exit watch while staying in dsapp
	if monitorValue:
		monitorValue = False
	else:
		ds.clear()
		# Clear dsapp/tmp
		ds.removeAllFiles("/opt/novell/datasync/tools/dsapp/tmp/")

		# Removes .pgpass if pgpass=true in dsapp.conf
		if pgpass:
			if sum(1 for line in open('/opt/novell/datasync/tools/dsapp/conf/dsapp.pid')) == 1:
				os.remove('/root/.pgpass')

		# Remove PID from dsapp.pid
		ds.removeLine('/opt/novell/datasync/tools/dsapp/conf/dsapp.pid', str(os.getpid()))

		# Reset the terminal
		print "Bye " + os.getlogin()
		sys.exit(1)

# SIG trap script
signal.signal(signal.SIGINT, signal_handler)

##################################################################################################
#	Set up script
##################################################################################################

# Create dsapp folder stucture
# TODO: ^

# Get dsapp PID
# TODO: Remove if statment once folder stucuture code is done
if not os.path.exists('/opt/novell/datasync/tools/dsapp/conf/'):
	os.makedirs('/opt/novell/datasync/tools/dsapp/conf/')
with open('/opt/novell/datasync/tools/dsapp/conf/dsapp.pid', 'w') as pidFile:
	pidFile.write(str(os.getpid()) + '\n')
	
# Clean up previous PIDs if not found
with open('/opt/novell/datasync/tools/dsapp/conf/dsapp.pid', 'r') as pidFile:
	for line in pidFile:
		if not ds.check_pid(int(line)):
			ds.removeLine('/opt/novell/datasync/tools/dsapp/conf/dsapp.pid', line)

# Get Console Size
windowSize = rows, columns = os.popen('stty size', 'r').read().split()
if windowSize[0] < '24' and windowSize[1] < '85':
	sys.exit("Terminal window does not meet size requirements\nCurrent Size: [ {0} x {1} ]\nPlease resize window to [80 x 24] or greater\n".format(windowSize[1], windowSize[0]))

# Switch Array for valid switches
switchArray=('-h', '--help', '--version', '--debug', '--bug', '-au', '--autoUpdate', '-ghc', '--gHealthCheck', '-f', '--force', '-ul', '--uploadLogs', '-c', '--check', '-s', '--status', '-up', '--update', '-v', '--vacuum', '-i', '--index', '-u', '--users', '-d', '--devices', '-db', '--database', '-ch', '--changeHost', '-re', '--restore', '--updateDsapp')

# Verify all passed in switches used are valid
switchCheck = sys.argv
del switchCheck[0]
switchError = False
for switch in switchCheck:
	if switch not in switchArray:
		print ("dsapp: {0} is not a valid command. See '--help'.".format(switch))
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

# Configure / Set dsapp.conf
# TODO: ^

# Get Hostname of server, and store in file (Only if file not found)
try:
	with open('/etc/HOSTNAME', 'r') as f:
		dsHostname = f.read()
	if not os.path.isfile(dsappConf + "/dsHostname.conf"):
		with open(dsappConf + '/dsHostname.conf', 'w') as f:
			f.write(dsHostname)
except IOError:
	pass
	logger.warning('Unable to get hostname of server')
	# TODO: Set flag to skip any hostname check in dsapp

# Store dsapp version (For new feature announce)
if not os.path.isfile(dsappConf + '/dsappVersion'):
		with open(dsappConf + '/dsappVersion', 'w') as f:
			f.write(dsappversion)

##################################################################################################
#	Initialization
##################################################################################################

# Load Menu (Get all needed variables)
if sys.argv == 1:
	ds.datasyncBanner(dsappversion)
	print "Loading menu..."
else:
	ds.clear()

# Read values from XML config
if isInstalled:
	# XML tree of each XML file
	mconfXML = ds.getXMLTree(mconf)
	ceconfXML = ds.getXMLTree(ceconf)
	wconfXML = ds.getXMLTree(wconf)
	gconfXML = ds.getXMLTree(gconf)

	ldapSecure = ds.xmlpath('.//configengine/ldap/secure', ceconfXML)
	ldapAdmin = ds.xmlpath('.//configengine/ldap/login/dn', ceconfXML)
	provisioning = ds.xmlpath('.//configengine/source/provisioning', ceconfXML)
	authentication = ds.xmlpath('.//configengine/source/authentication', ceconfXML)
	ldapEnabled = ds.xmlpath('.//configengine/ldap/enabled', ceconfXML)
	groupContainer = ds.xmlpath('.//configengine/ldap/groupContainer', ceconfXML)
	userContainer = ds.xmlpath('.//configengine/ldap/userContainer', ceconfXML)
	webAdmins = ds.xmlpath('.//configengine/ldap/admins/dn', ceconfXML)

	ldapAddress = ds.xmlpath('.//settings/custom/ldapAddress', mconfXML)
	ldapPort = ds.xmlpath('.//settings/custom/ldapPort', mconfXML)
	mPort = ds.xmlpath('.//settings/custom/listenPort', mconfXML)
	mSecure = ds.xmlpath('.//settings/custom/ssl', mconfXML)
	mlistenAddress = ds.xmlpath('.//settings/custom/listenAddress', mconfXML)
	galUserName = ds.xmlpath('.//settings/custom/galUserName', mconfXML)
	mAttachSize = ds.xmlpath('.//settings/custom/attachmentMaxSize', mconfXML)

	sListenAddress = ds.xmlpath('.//settings/custom/listeningLocation', gconfXML)
	trustedName = ds.xmlpath('.//settings/custom/trustedAppName', gconfXML)
	gPort = ds.xmlpath('.//settings/custom/port', gconfXML)
	gAttachSize = ds.xmlpath('.//settings/custom/attachmentMaxSize', gconfXML)
	gListenAddress = ds.xmlpath('.//settings/custom/soapServer', gconfXML).split("://",1)[1].split(":",1)[0]
	sPort = ds.xmlpath('.//settings/custom/soapServer', gconfXML).split("://",1)[1].split(":",1)[1].split("/",1)[0]
	sSecure = ds.xmlpath('.//settings/custom/soapServer', gconfXML).split("://",1)[0]

	wPort = ds.xmlpath('.//server/port', wconfXML)

##################################################################################################
#	Main
##################################################################################################


ds.datasyncBanner(dsappversion)
ds.eContinue()