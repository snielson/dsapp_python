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
import subprocess
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

sys.path.append('./lib') # TODO: Give absolute path when done.
import dsappDefinitions as ds
ds.set_dsappversion(dsappversion)

import spin

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
config_files = {}
config_files['mconf'] = "/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml"
config_files['gconf'] = "/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/groupwise/connector.xml"
config_files['ceconf'] = "/etc/datasync/configengine/configengine.xml"
config_files['econf'] = "/etc/datasync/configengine/engines/default/engine.xml"
config_files['wconf'] = "/etc/datasync/webadmin/server.xml"

# Test server paths
# config_files['mconf'] = "/root/Desktop/confXML/mobility/connector.xml"
# config_files['gconf'] = "/root/Desktop/confXML/groupwise/connector.xml"
# config_files['ceconf'] = "/root/Desktop/confXML/configengine.xml"
# config_files['econf'] = "/root/Desktop/confXML/engine.xml"
# config_files['wconf'] = "/root/Desktop/confXML/server.xml"

# Misc variables
serverinfo = "/etc/*release"
rpminfo = "datasync"
dsapp_tar = "dsapp.tgz"
isNum = '^[0-9]+$'
ds_20x= 2000
ds_21x = 2100
previousVersion = 20153
latestVersion = 210230
rcScript = None
mobilityVersion = 0
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

# TODO: Change logger level via switch
logging.config.fileConfig(dsappLogSettings)
logger = logging.getLogger(__name__)
logger.info('------------- Starting dsapp -------------')

##################################################################################################
#	Setup local definitions
##################################################################################################

# Define Variables for Eenou+ (2.x)
def declareVariables2():
	global ds_version
	global rcScript
	logger.debug('Setting version variables for 2.X')
	mAlog = log + "/connectors/mobility-agent.log"
	gAlog = log + "/connectors/groupwise-agent.log"
	mlog = log + "/connectors/mobility.log"
	glog = log + "/connectors/groupwise.log"
	rcScript = "rcgms"

# Define Variables for Pre-Eenou (1.x)
def declareVariables1():
	global ds_version
	global rcScript
	logger.debug('Setting version variables for 1.X')
	mAlog = log + "/connectors/default.pipeline1.mobility-AppInterface.log"
	gAlog = log + "/connectors/default.pipeline1.groupwise-AppInterface.log"
	mlog = log + "/connectors/default.pipeline1.mobility.log"
	glog = log + "/connectors/default.pipeline1.groupwise.log"
	rcScript="rcdatasync"

def exit_cleanup():
	try:
		if spinner.isAlive():
			spinner.stop()
	except NameError:
		pass

	# Clear dsapp/tmp
	ds.removeAllFiles("/opt/novell/datasync/tools/dsapp/tmp/")
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
	Config.read(dsappSettings)
	Config.set('Misc', 'new.feature', False)
	with open(dsappSettings, 'wb') as cfgfile:
		Config.write(cfgfile)

def updateDsapp(publicVersion):
	print 'Updating dsapp to v%s' % (publicVersion)
	ds.logger.info('Updating dsapp to v%s' % (publicVersion))

	# Download new version & extract
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
				ds.logger.info('dsapp is up-to-date at v%s' % dsappversion)

def getDSVersion():
	if isInstalled:
		with open(version) as f:
			value = f.read().translate(None, '.')[0:4]
		return value

def setVariables():
	# Depends on version 1.x or 2.x
	if isInstalled:
		if dsVersion > ds_20x:
			declareVariables2()
		else:
			declareVariables1()

def dsUpdate(repo):
	spinner = set_spinner()
	if '%s/common/lib' % dirOptMobility not in sys.path:
		sys.path.append(dirOptMobility + '/common/lib/')
	import upgrade

	ref = subprocess.Popen(['zypper', 'ref', '-f', repo], stdout=subprocess.PIPE)
	ref.wait()
	zLU = subprocess.Popen(['zypper', 'lu', '-r', repo], stdout=subprocess.PIPE).communicate()
	if 'No updates found' in zLU[0]:
		print "\nMobility is already this version, or newer"
		ds.logger.info('Unable to update mobility. Same version or newer')
		if ds.askYesOrNo('List %s packages' % repo):
			pkg = subprocess.Popen(['zypper', 'pa', '-ir', '%s' % repo])
			pkg.wait()
			ds.logger.info('Listing %s packages' % repo)
			print
			if ds.askYesOrNo("Force install %s packages" % repo):
				print "Force updating Mobility.. ",
				ds.logger.info('Force updating Mobility..')
				spinner.start(); time.sleep(.000001)
				time1 = time.time()
				install = subprocess.Popen(['zypper', '--non-interactive', 'install', '--force', '%s:' % repo], stdout=subprocess.PIPE)
				install.wait()
				spinner.stop(); print
				time2 = time.time()
				ds.logger.info("Foce update Mobility package complete")
				ds.logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
				print "\nPlease run 'sh %s/update.sh' to complete the upgrade" % dirOptMobility
	else:
		print "Updating Mobility.. ",
		ds.logger.info('Updating Mobility started')
		spinner.start(); time.sleep(.000001)
		time1 = time.time()
		install = subprocess.Popen(['zypper', '--non-interactive', 'update', '--force', '-r', '%s' % repo], stdout=subprocess.PIPE)
		install.wait()
		spinner.stop(); print
		time2 = time.time()
		ds.logger.info("Updating Mobility package complete")
		ds.logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

		# Update config file
		dsVersion = getDSVersion()
		Config.read(dsappSettings)
		Config.set('Misc', 'mobility.version', dsVersion)
		with open(dsappSettings, 'wb') as cfgfile:
			Config.write(cfgfile)
		setVariables()
		ds.logger.info('Updating Mobility schema started')
		time1 = time.time()
		ds.rcDS(rcScript,'stop')
		os.environ["FEEDBACK"] = ""
		os.environ["LOGGER"] = ""

		pre = upgrade.Pre_Update()
		if pre.get_it_done():
			update = upgrade.connectorUpgrade(pre.version)
			update.install_monitor()
			update.service_upgrade()
		time2 = time.time()
		ds.logger.info("Updating Mobility schema complete")
		ds.logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

		p = subprocess.Popen(['rcpostgresql', 'stop'], stdout=subprocess.PIPE)
		p.wait()
		pids = ds.get_pid('/usr/bin/python')
		for pid in pids:
			ds.kill_pid(int(pid), 9)
		
		# Update config file
		dsVersion = getDSVersion()
		Config.read(dsappSettings)
		Config.set('Misc', 'mobility.version', dsVersion)
		with open(dsappSettings, 'wb') as cfgfile:
			Config.write(cfgfile)
		setVariables()

		# getExactMobilityVersion
		p = subprocess.Popen(['rcpostgresql', 'start'], stdout=subprocess.PIPE)
		p.wait()
		ds.rcDS(rcScript, 'start')

		with open(dirOptMobility + '/version') as v:
			version = v.read()
		print "\nYour Mobility product has been successfully updated to %s" % version
		ds.logger.info('Mobility product successfully updated to %s' % version)


##################################################################################################
#	Set up script
##################################################################################################

# Disclaimer
# TODO: Always load on start? or work on placing at bottom of main menu
# ds.print_disclaimer(dsappversion)

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
with open(dsappConf + '/dsapp.pid', 'a') as pidFile:
	pidFile.write(str(os.getpid()) + '\n')
	
# Clean up previous PIDs if not found
with open(dsappConf + '/dsapp.pid', 'r') as pidFile:
	for line in pidFile:
		if not ds.check_pid(int(line)):
			ds.removeLine(dsappConf + '/dsapp.pid', line)

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

# Get mobility version
dsVersion = getDSVersion()

# Get Hostname of server, and store in setting.cfg
if not os.path.isfile(dsappSettings):
	dsHostname = os.popen('echo `hostname -f`').read().rstrip()

# Create setting.cfg if not found
if not os.path.isfile(dsappSettings):
	with open(dsappSettings, 'w') as cfgfile:
		Config.add_section('Misc')
		Config.add_section('Settings')
		Config.set('Misc', 'hostname', dsHostname)
		Config.set('Settings', 'new.feature', False)
		Config.set('Misc', 'dsapp.version', dsappversion)
		Config.set('Settings', 'auto.update', True)
		Config.set('Misc', 'mobility.version', dsVersion)
		Config.write(cfgfile)
		
# Update dsVersion in settings.cfg
Config.read(dsappSettings)
Config.set('Misc', 'mobility.version', dsVersion)
with open(dsappSettings, 'wb') as cfgfile:
	Config.write(cfgfile)

# Assign variables based on settings.cfg
Config.read(dsappSettings)
dsHostname = Config.get('Misc', 'hostname')
newFeature = Config.getboolean('Settings', 'new.feature')
autoUpdate = Config.getboolean('Settings', 'auto.update')

# Get Mobility Version
mobilityVersion = ds.getVersion(isInstalled, version)

# Only call autoUpdateDsapp() if filename is dsapp.pyc
if __file__ == 'dsapp.pyc':
	autoUpdateDsapp()

# Get current working directory
cPWD = os.getcwd()

# Set up variables based on version
setVariables()

##################################################################################################
#	Initialization
##################################################################################################

# Load Menu (Get all needed variables)
if len(sys.argv) == 0:
	ds.datasyncBanner(dsappversion)

	# Read values from XML config
	if isInstalled:
		# XML tree of each XML file
		logger.info('Building XML trees started')
		time1 = time.time()
		XMLconfig = {}
		logger.debug('Building %s tree from: %s' % ('mconfXML', config_files['mconf']))
		XMLconfig['mconf'] = ds.getXMLTree(config_files['mconf'])
		logger.debug('Building %s tree from: %s' % ('econfXML', config_files['econf']))
		XMLconfig['econf'] = ds.getXMLTree(config_files['econf'])
		logger.debug('Building %s tree from: %s' % ('ceconfXML', config_files['ceconf']))
		XMLconfig['ceconf'] = ds.getXMLTree(config_files['ceconf'])
		logger.debug('Building %s tree from: %s' % ('wconfXML', config_files['wconf']))
		XMLconfig['wconf'] = ds.getXMLTree(config_files['wconf'])
		logger.debug('Building %s tree from: %s' % ('gconfXML', config_files['gconf']))
		XMLconfig['gconf'] = ds.getXMLTree(config_files['gconf'])
		time2 = time.time()
		logger.info('Building XML trees complete')
		logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

		# Check current hostname with stored hostname
		logger.info('Checking hostname')
		ds.check_hostname(dsHostname, XMLconfig, config_files)

		print "Loading settings.. ",
		# Start spinner
		spinner = set_spinner()
		spinner.start(); time.sleep(.000001)

		time1 = time.time()
		logger.info('Assigning variables from XML started')
		
		logger.debug('Assigning %s from %s' % ('provisioning', 'ceconfXML'))
		provisioning = ds.xmlpath('.//configengine/source/provisioning', XMLconfig['ceconf'])
		logger.debug('Assigning %s from %s' % ('authentication', 'ceconfXML'))
		authentication = ds.xmlpath('.//configengine/source/authentication', XMLconfig['ceconf'])
		logger.debug('Assigning %s from %s' % ('smtpPassword', 'ceconfXML'))
		smtpPassword = ds.getDecrypted('.//configengine/notification/smtpPassword', XMLconfig['ceconf'], './/configengine/notification/protected')

		# LDAP values
		ldapConfig = {}
		logger.debug('Assigning %s from %s' % ('ldap secure', 'ceconfXML'))
		ldapConfig['secure'] = ds.xmlpath('.//configengine/ldap/secure', XMLconfig['ceconf'])
		logger.debug('Assigning %s from %s' % ('login', 'ceconfXML'))
		ldapConfig['login'] = ds.xmlpath('.//configengine/ldap/login/dn', XMLconfig['ceconf'])
		logger.debug('Assigning %s from %s' % ('password', 'ceconfXML'))
		ldapConfig['pass'] = ds.getDecrypted('.//configengine/ldap/login/password', XMLconfig['ceconf'], './/configengine/ldap/login/protected')
		
		logger.debug('Assigning %s from %s' % ('ldap enabled', 'ceconfXML'))
		ldapConfig['enabled'] = ds.xmlpath('.//configengine/ldap/enabled', XMLconfig['ceconf'])
		logger.debug('Assigning %s from %s' % ('group container', 'ceconfXML'))
		ldapConfig['group'] = ds.xmlpath('.//configengine/ldap/groupContainer', XMLconfig['ceconf'])
		logger.debug('Assigning %s from %s' % ('user container', 'ceconfXML'))
		ldapConfig['user'] = ds.xmlpath('.//configengine/ldap/userContainer', XMLconfig['ceconf'])
		logger.debug('Assigning %s from %s' % ('admins', 'ceconfXML'))
		ldapConfig['admins'] = ds.xmlpath('.//configengine/ldap/admins/dn', XMLconfig['ceconf'])

		# Postgresql values
		dbConfig = {}
		logger.debug('Assigning %s from %s' % ('Postgresql Username', 'ceconfXML'))
		dbConfig['user'] = ds.xmlpath('.//configengine/database/username', XMLconfig['ceconf'])
		logger.debug('Assigning %s from %s' % ('Postgresql Hostname', 'ceconfXML'))
		dbConfig['host'] = ds.xmlpath('.//configengine/database/hostname', XMLconfig['ceconf'])
		logger.debug('Assigning %s from %s' % ('Postgresql Port', 'ceconfXML'))
		dbConfig['port'] = ds.xmlpath('.//configengine/database/port', XMLconfig['ceconf'])
		logger.debug('Assigning %s from %s' % ('Postgresql Database', 'ceconfXML'))
		dbConfig['db'] = ds.xmlpath('.//configengine/database/db', XMLconfig['ceconf'])
		logger.debug('Assigning %s from %s' % ('Postgresql Password', 'ceconfXML'))
		dbConfig['pass'] = ds.getDecrypted('.//configengine/database/password', XMLconfig['ceconf'], './/configengine/database/protected')

		logger.debug('Assigning %s from %s' % ('ldapAddress', 'mconfXML'))
		ldapAddress = ds.xmlpath('.//settings/custom/ldapAddress', XMLconfig['mconf'])
		logger.debug('Assigning %s from %s' % ('ldapPort', 'mconfXML'))
		ldapPort = ds.xmlpath('.//settings/custom/ldapPort', XMLconfig['mconf'])
		logger.debug('Assigning %s from %s' % ('mPort', 'mconfXML'))
		mPort = ds.xmlpath('.//settings/custom/listenPort', XMLconfig['mconf'])
		logger.debug('Assigning %s from %s' % ('mSecure', 'mconfXML'))
		mSecure = ds.xmlpath('.//settings/custom/ssl', XMLconfig['mconf'])
		logger.debug('Assigning %s from %s' % ('mlistenAddress', 'mconfXML'))
		mlistenAddress = ds.xmlpath('.//settings/custom/listenAddress', XMLconfig['mconf'])
		logger.debug('Assigning %s from %s' % ('galUserName', 'mconfXML'))
		galUserName = ds.xmlpath('.//settings/custom/galUserName', XMLconfig['mconf'])
		logger.debug('Assigning %s from %s' % ('mAttachSize', 'mconfXML'))
		mAttachSize = ds.xmlpath('.//settings/custom/attachmentMaxSize', XMLconfig['mconf'])

		logger.debug('Assigning %s from %s' % ('sListenAddress', 'gconfXML'))
		sListenAddress = ds.xmlpath('.//settings/custom/listeningLocation', XMLconfig['gconf'])
		logger.debug('Assigning %s from %s' % ('gPort', 'gconfXML'))
		gPort = ds.xmlpath('.//settings/custom/port', XMLconfig['gconf'])
		logger.debug('Assigning %s from %s' % ('gAttachSize', 'gconfXML'))
		gAttachSize = ds.xmlpath('.//settings/custom/attachmentMaxSize', XMLconfig['gconf'])
		logger.debug('Assigning %s from %s' % ('gListenAddress', 'gconfXML'))
		gListenAddress = ds.xmlpath('.//settings/custom/soapServer', XMLconfig['gconf']).split("://",1)[1].split(":",1)[0]
		logger.debug('Assigning %s from %s' % ('sPort', 'gconfXML'))
		sPort = ds.xmlpath('.//settings/custom/soapServer', XMLconfig['gconf']).split("://",1)[1].split(":",1)[1].split("/",1)[0]
		logger.debug('Assigning %s from %s' % ('sSecure', 'gconfXML'))
		sSecure = ds.xmlpath('.//settings/custom/soapServer', XMLconfig['gconf']).split("://",1)[0]
		# Trusted app values
		trustedConfig = {}
		logger.debug('Assigning %s from %s' % ('trusted app name', 'gconfXML'))
		trustedConfig['name'] = ds.xmlpath('.//settings/custom/trustedAppName', XMLconfig['gconf'])
		logger.debug('Assigning %s from %s' % ('trusted app key', 'gconfXML'))
		trustedConfig['key'] = ds.getDecrypted('.//settings/custom/trustedAppKey',XMLconfig['gconf'], './/settings/custom/protected')

		logger.debug('Assigning %s from %s' % ('wPort', 'wconfXML'))
		wPort = ds.xmlpath('.//server/port', XMLconfig['wconf'])

		time2 = time.time()
		logger.info('Assigning variables from XML complete')
		logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
		# Stop spinner
		spinner.stop(); print '\n'

else:
	ds.clear()

# Test database connection
# TODO : TEST on server with dbs
if not ds.checkPostgresql(dbConfig):
	sys.exit(1)

##################################################################################################
#	Main
##################################################################################################
import menus

# TEST CODE / Definitions
ds.datasyncBanner(dsappversion)

# ds.remove_user(dbConfig)
# ds.rcDS(rcScript, 'stop')
# ds.cuso(dbConfig)
# ds.rcDS(rcScript, 'start')
# ds.monitor_syncing_users(dbConfig)
# menus.main_menu()



ds.eContinue()
sys.exit(0)
