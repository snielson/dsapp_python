#!/usr/bin/env python
##################################################################################################
#
#	<Python 2.6>
#	dsapp was created to help customers and support engineers troubleshoot
#	and solve common issues for the Novell GroupWise Mobility product.
#
#	Rewritten in python by: Shane Nielson <snielson@projectuminfinitas.com>
#	Original dsapp by: Shane Nielson & Tyler Harris
#
##################################################################################################
__author__ = "Shane Nielson"
__credits__ = "Tyler Harris"
__maintainer__ = "Shane Nielson"
__email__ = "snielson@projectuminfinitas.com"

dsappversion='240'

##################################################################################################
#	Imports
##################################################################################################

import os
import sys
import signal
import logging
import logging.config
import time
import atexit
import subprocess
import traceback
import ConfigParser
Config = ConfigParser.ConfigParser()

# Check for dsapp/logs folder (Needed for logs)
if not os.path.exists('/opt/novell/datasync/tools/dsapp/logs/'):
	os.makedirs('/opt/novell/datasync/tools/dsapp/logs/')

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import spin
import imp
pydoc = imp.load_source('pydoc', os.path.dirname(os.path.realpath(__file__)) + '/lib/pydoc.py')
# import pydoc

##################################################################################################
#	Start up check
##################################################################################################

# Make sure user is root
if (os.getuid() != 0):
	print ("Root user required to run this script")
	sys.exit(1)

##################################################################################################
#	Global Variables
##################################################################################################

# Start up variables
installedConnector = "/etc/init.d/datasync-connectors"

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

# Configuration File
config_files = dict()
config_files['mconf'] = "/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml"
config_files['gconf'] = "/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/groupwise/connector.xml"
config_files['ceconf'] = "/etc/datasync/configengine/configengine.xml"
config_files['econf'] = "/etc/datasync/configengine/engines/default/engine.xml"
config_files['wconf'] = "/etc/datasync/webadmin/server.xml"

# Misc variables
ds_1x= 1
ds_2x = 2
ds_14x = 14
mobilityVersion = 0
version = "/opt/novell/datasync/version"
osVersion = None

# Mobility Directories
log = "/var/log/datasync"

# Mobility logs
configenginelog = log + "/configengine/configengine.log"
connectormanagerlog = log + "/syncengine/connectorManager.log"
syncenginelog = log + "/syncengine/engine.log"
monitorlog = log + "/monitorengine/monitor.log"
systemagentlog = log + "/monitorengine/systemagent.log"
updatelog = log + "/update.log"
webadminlog = log + "/webadmin/server.log"

# dsapp Conf / Logs
dsappSettings = dsappConf + "/setting.cfg"
dsappLogSettings = dsappConf + "/logging.cfg"
dsappLog = dsappConf + "/dsapp.log"

# Create dsapp folder stucture
dsapp_folders = [dsappDirectory, dsappConf, dsappLogs, dsappBackup, dsapptmp, dsappupload, rootDownloads, dsapplib, dsappdata]
for folder in dsapp_folders:
	if not os.path.exists(folder):
		os.makedirs(folder)

# Create setting.cfg if not found
if not os.path.isfile(dsappSettings):
	dsHostname = os.popen('echo `hostname -f`').read().rstrip()
	with open(dsappSettings, 'w') as cfgfile:
		Config.add_section('Misc')
		Config.add_section('Settings')
		Config.add_section('Log')
		Config.add_section('GHC')
		Config.add_section('FTF URL')
		Config.add_section('Update URL')
		Config.add_section('Upload URL')
		Config.add_section('dsapp URL')
		Config.add_section('Upload Logs')
		Config.set('FTF URL', 'check.service.address', 'ftp.novell.com')
		Config.set('Update URL', 'check.service.address', 'ftp.novell.com')
		Config.set('dsapp URL', 'check.service.address', 'www.github.com')
		Config.set('Upload URL', 'check.service.address', 'ftp.novell.com')
		Config.set('FTF URL', 'check.service.port', 21)
		Config.set('Update URL', 'check.service.port', 21)
		Config.set('dsapp URL', 'check.service.port', 443)
		Config.set('Upload URL', 'check.service.port', 21)
		Config.set('FTF URL', 'download.address', 'ftp://ftp.novell.com/outgoing/')
		Config.set('Update URL', 'download.address', 'ftp://ftp.novell.com/outgoing/')
		Config.set('dsapp URL', 'download.address', 'https://github.com/snielson/dsapp_python/releases/download/latest/')
		Config.set('Upload URL', 'address', 'ftp://ftp.novell.com/incoming/')
		Config.set('dsapp URL', 'download.filename', 'dsapp.zip')
		Config.set('dsapp URL', 'version.download.filename', 'dsapp-version.info')
		Config.set('Misc', 'dsapp.version', dsappversion)
		Config.set('Misc', 'hostname', dsHostname)
		Config.set('Settings', 'auto.update', True)
		Config.set('Settings', 'new.feature', False)
		Config.set('Log', 'nightly.logs', 5)
		Config.set('Log', 'datasync.log.maxage', 14)
		Config.set('Log', 'dsapp.log.maxage', 14)
		Config.set('GHC', 'ntp.server', 'time.nist.gov')
		Config.set('Misc', 'sles.version', None)
		Config.set('Upload Logs', 'mobility.agent', 3)
		Config.set('Upload Logs', 'mobility', 3)
		Config.set('Upload Logs', 'groupwise.agent', 3)
		Config.set('Upload Logs', 'groupwise', 3)
		Config.set('Upload Logs', 'messages', 2)
		Config.set('Upload Logs', 'postgres', 3)
		Config.write(cfgfile)

# Create defaults to config if missing
Config.read(dsappSettings)
if not Config.has_section('Upload Logs'): # Added v239
	Config.add_section('Upload Logs')
	Config.set('Upload Logs', 'mobility.agent', 3)
	Config.set('Upload Logs', 'mobility', 3)
	Config.set('Upload Logs', 'groupwise.agent', 3)
	Config.set('Upload Logs', 'groupwise', 3)
	Config.set('Upload Logs', 'messages', 2)
	Config.set('Upload Logs', 'postgres', 3)

with open(dsappSettings, 'wb') as cfgfile:
	Config.write(cfgfile)


import dsapp_Definitions as ds

##################################################################################################
#	Log Settings
##################################################################################################

logging.config.fileConfig(dsappLogSettings)
excep_logger = logging.getLogger('exceptions_log')
logger = logging.getLogger(__name__)
logger.info('------------- Starting dsapp -------------')
if not sys.stdout.isatty():
	logger.info('Running in CRON')

##################################################################################################
#	Setup local definitions
##################################################################################################

def exit_cleanup():
	logger.debug("Running exit cleanup..")
	try:
		if spinner.isAlive():
			spinner.stop()
			print;ds.eContinue()
	except NameError:
		pass

	# Clear dsapp/tmp
	ds.removeAllFolders(dsapptmp)
	ds.removeAllFiles(dsapptmp)

	# Reset terminal (for blank text bug on Ctrl + C)
	os.system('stty sane')
	
	logger.info('------------- Successfully shutdown dsapp -------------')

def signal_handler_SIGINT(signal, frame):
	# Clean up dsapp
	exit_cleanup()
	sys.exit(0)

def my_handler(type, value, tb):
	tmp = traceback.format_exception(type, value, tb)
	logger.error("EXCEPTION: See exception.log")
	excep_logger.error("Uncaught exception:\n%s" % ''.join(tmp).strip())
	print ''.join(tmp).strip()

# Install exception handler
sys.excepthook = my_handler

def set_spinner():
	spinner = spin.progress_bar_loading()
	spinner.setDaemon(True)
	return spinner

##################################################################################################
#	Set up script
##################################################################################################

# Register exit_cleanup with atexit
atexit.register(exit_cleanup)

# Get Console Size
if sys.stdout.isatty():
	windowSize = rows, columns = os.popen('stty size', 'r').read().split()
	if int(windowSize[0]) < int(24) or int(windowSize[1]) < int(80):
		print ("Terminal window does not meet size requirements\nCurrent Size: [%s x %s]\nPlease resize window to [80 x 24] or greater\n" % (windowSize[1],windowSize[0]))
		sys.exit(1)

# Check OS version 
try:
	osVersion = int(ds.getOS_Version())
	logger.info("Detected SLES version %s" % osVersion)
except:
	logger.warning("Unable to detect SLES version")


##################################################################################################
#	Check Switches
##################################################################################################
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--version', action='version', version='%(prog)s (version {version})'.format(version=dsappversion))
parser.add_argument('--updateDsapp', action='store_true', dest='dsUpdate', help='Updates dsapp to latest version')
parser.add_argument('--autoUpdate', action='store_true', dest='autoUpdate', help='Toggles dsapp auto update')
parser.add_argument('--bug', dest='bug', action='store_true', help="How to report a issue for dsapp")
parser.add_argument('-ghc', '--gHealthCheck', action='store_true', dest='ghc', help='Run dsapp gneral health check')
parser.add_argument('-ul', '--uploadLogs', action='store_true', dest='upload', help='Upload mobility logs to FTP')
parser.add_argument('-c', '--check', action='store_true', dest='check', help='Check nightly maintenance')
parser.add_argument('-s', '--status', action='store_true', dest='status', help='Show sync status of connectors')
parser.add_argument('-up', '--update', action='store_true', dest='update', help='Update mobility (URL)')
parser.add_argument('-v', '--vacuum', action='store_true', dest='vacuum', help='Vacuum postgres database')
parser.add_argument('-i', '--index', action='store_true', dest='index', help='Index postgres database')
parser.add_argument('-u', '--users', action='store_true', dest='users', help='Print list of all users with count')
parser.add_argument('-d', '--devices', action='store_true', dest='devices', help='Print list of all devices with count')
parser.add_argument('-ch', '--changeHost', action='store_true', dest='host', help='Fix mobility encryption with old hostname')
parser.add_argument('-f', '--force', action='store_true', dest='force', help='Force runs dsapp')
parser.add_argument('-db', '--database', action='store_true', dest='db', help='Change database password')
parser.add_argument('-cl', '--clear', action='store_true', dest='clear', help='Remove encryption from XMLs')
parser.add_argument('--config', dest='re', choices=['backup', 'restore'], help='Backup settings or install Mobility with backup')
parser.add_argument('--setlog', dest='loglevel', choices=['debug','info','warning'], help='Set the logging level')
parser.add_argument('--debugMenu', action='store_true', dest='debugMenu', help=argparse.SUPPRESS)
args = parser.parse_args()
logger.debug("Switches: %s" % args)

if args.re == 'restore':
	import dsapp_re
	dsapp_re.install_settings()
	print; ds.eContinue()
	sys.exit(0)

if args.bug:
	ds.datasyncBanner(dsappversion)
	print "Report issues to: https://github.com/snielson/dsapp_python/issues\n"
	print "Useful logs can be located at:\n/opt/novell/datasync/tools/dsapp/logs/\nSet dsapp logs into debug for more information `dsapp --setlog debug`\n"
	print "Feel free to email %s directly at <%s>" % (__author__, __email__)
	sys.exit(0)

if args.dsUpdate:
	ds.autoUpdateDsapp(True)
	ds.eContinue()
	sys.exit(0)

# Set logs if loglevel switch passed in
if args.loglevel:
	Config.read(dsappLogSettings)
	Config.set('logger___main__', 'level', args.loglevel.upper())
	Config.set('logger_dsapp_Definitions', 'level', args.loglevel.upper())
	with open(dsappLogSettings, 'wb') as logFile:
		Config.write(logFile)
	print "dsapp logs set to %s" % args.loglevel.upper()
	logger.info("dsapp logs set to %s" % args.loglevel.upper())
	sys.exit(0)

if args.autoUpdate:
	Config.read(dsappSettings)
	temp = Config.getboolean('Settings', 'auto.update')
	temp = not temp
	Config.set('Settings', 'auto.update', temp)
	with open(dsappSettings, 'wb') as cfgfile:
		logger.debug("Writing: [Settings] auto.update = %s" % temp)
		Config.write(cfgfile)
	print ("Set auto update to '%s'" % temp)
	logger.info("Set auto update to '%s'" % temp)
	sys.exit(0)

# Check / set force mode
forceMode = args.force

if args.clear or args.db:
	forceMode = True

# Check if installed
if not ds.checkInstall(forceMode, installedConnector):
	sys.exit(1)

# Give force mode warning
if forceMode:
	if not args.re and not args.clear and not args.db:
		ds.datasyncBanner(dsappversion)
		print ("Running force mode. Some options may not work properly.\n")
		logger.warning('Running in force mode')
		ds.eContinue()

# Get mobility version
dsVersion = ds.getDSVersion(forceMode)

# Debug logging: dsVersion
if dsVersion >= ds_14x:
	logger.debug('Version : Mobility 14x')
elif dsVersion >= ds_2x:
	logger.debug('Version : Mobility 2x')
elif dsVersion >= ds_1x:
	logger.debug('Version : Mobility 1x')
		
# Update values in settings.cfg
Config.read(dsappSettings)
Config.set('Misc', 'mobility.version', dsVersion)
Config.set('Misc', 'dsapp.version', dsappversion)
Config.set('Misc', 'sles.version', osVersion)
with open(dsappSettings, 'wb') as cfgfile:
	logger.debug("Writing: [Misc] mobility.version = %s" % dsVersion)
	logger.debug("Writing: [Misc] dsapp.version = %s" % dsappversion)
	logger.debug("Writing: [Misc] sles.version = %s" % osVersion)
	Config.write(cfgfile)

# Assign variables based on settings.cfg
Config.read(dsappSettings)
dsHostname = Config.get('Misc', 'hostname')

# Get Mobility Version
if not forceMode:
	mobilityVersion = ds.getVersion(ds.checkInstall(forceMode, installedConnector), version)

# Only call autoUpdateDsapp() if no args are passed
# if os.path.basename(__file__) == 'dsapp.py' and len(sys.argv) == 1:
if len(sys.argv) == 1:
	ds.autoUpdateDsapp()

##################################################################################################
#	Initialization
##################################################################################################

# Check for new features
ds.announceNewFeature()

# Load Menu (Get all needed variables)
XMLconfig = dict()
authConfig = dict()
ldapConfig = dict()
dbConfig = dict()
mobilityConfig = dict()
gwConfig = dict()
trustedConfig = dict()
webConfig = dict()

ds.datasyncBanner(dsappversion)

# XML tree of each XML file
logger.info('Building XML trees started')
time1 = time.time()
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
if args.host:
	print ("This should only be used if the hostname encryption is not detected by dsapp")
	if ds.askYesOrNo("Continue to fix encryption"):
		old_host = raw_input("Previous hostname: ")
		print
		ds.check_hostname(old_host, XMLconfig, config_files, forceFix=True)
	print; sys.exit(0)

elif not args.host:
	logger.info('Checking hostname')
	if not ds.check_hostname(dsHostname, XMLconfig, config_files):
		new_host = os.popen('echo `hostname -f`').read().rstrip()
		print ("\nUnable to read encryption with current hostname '%s'\n" % new_host)
		logger.error("Unable to read encryption with current hostname '%s'" % new_host)
		ds.eContinue()
		sys.exit(1)

print "Loading settings.. ",
# Start spinner
spinner = set_spinner()
spinner.start(); time.sleep(.000001)

time1 = time.time()
logger.info('Assigning variables from XML started')

# Provision / auth Values
logger.debug('Assigning %s from %s' % ('provisioning', 'ceconfXML'))
authConfig['provisioning'] = ds.xmlpath('.//configengine/source/provisioning', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('authentication', 'ceconfXML'))
authConfig['authentication'] = ds.xmlpath('.//configengine/source/authentication', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('smtpPassword', 'ceconfXML'))
authConfig['smtpPassword'] = ds.getDecrypted('.//configengine/notification/smtpPassword', XMLconfig['ceconf'], './/configengine/notification/protected', force=forceMode)

# LDAP values
logger.debug('Assigning %s from %s' % ('ldap secure', 'ceconfXML'))
ldapConfig['secure'] = ds.xmlpath('.//configengine/ldap/secure', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('login', 'ceconfXML'))
ldapConfig['login'] = ds.xmlpath('.//configengine/ldap/login/dn', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('password', 'ceconfXML'))
ldapConfig['pass'] = ds.getDecrypted('.//configengine/ldap/login/password', XMLconfig['ceconf'], './/configengine/ldap/login/protected', force=forceMode)
ldapConfig['enc_pass'] = ds.xmlpath('.//configengine/ldap/login/password', XMLconfig['ceconf'])

logger.debug('Assigning %s from %s' % ('ldap enabled', 'ceconfXML'))
ldapConfig['enabled'] = ds.xmlpath('.//configengine/ldap/enabled', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('LDAP group container', 'ceconfXML'))
ldapConfig['group'] = ds.xmlpath_findall('.//configengine/ldap/groupContainer', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('LDAP user container', 'ceconfXML'))
ldapConfig['user'] = ds.xmlpath_findall('.//configengine/ldap/userContainer', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('LDAP admins', 'ceconfXML'))
ldapConfig['admins'] = ds.xmlpath_findall('.//configengine/ldap/admins/dn', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('LDAP port', 'ceconfXML'))
ldapConfig['port'] = ds.xmlpath('.//configengine/ldap/port', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('LDAP host', 'ceconfXML'))
ldapConfig['host'] = ds.xmlpath('.//configengine/ldap/hostname', XMLconfig['ceconf'])

# Postgresql values
logger.debug('Assigning %s from %s' % ('Postgresql Username', 'ceconfXML'))
dbConfig['user'] = ds.xmlpath('.//configengine/database/username', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('Postgresql Hostname', 'ceconfXML'))
dbConfig['host'] = ds.xmlpath('.//configengine/database/hostname', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('Postgresql Port', 'ceconfXML'))
dbConfig['port'] = ds.xmlpath('.//configengine/database/port', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('Postgresql Database', 'ceconfXML'))
dbConfig['db'] = ds.xmlpath('.//configengine/database/db', XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('Postgresql Password', 'ceconfXML'))
dbConfig['pass'] = ds.getDecrypted('.//configengine/database/password', XMLconfig['ceconf'], './/configengine/database/protected', force=forceMode)

logger.debug('Assigning %s from %s' % ('Mobility connector mPort', 'mconfXML'))
mobilityConfig['mPort'] = ds.xmlpath('.//settings/custom/listenPort', XMLconfig['mconf'])
logger.debug('Assigning %s from %s' % ('Mobility connector mSecure', 'mconfXML'))
mobilityConfig['mSecure'] = ds.xmlpath('.//settings/custom/ssl', XMLconfig['mconf'])
logger.debug('Assigning %s from %s' % ('Mobility connector mlistenAddress', 'mconfXML'))
mobilityConfig['mlistenAddress'] = ds.xmlpath('.//settings/custom/listenAddress', XMLconfig['mconf'])
logger.debug('Assigning %s from %s' % ('Mobility connector galUserName', 'mconfXML'))
mobilityConfig['galUserName'] = ds.xmlpath('.//settings/custom/galUserName', XMLconfig['mconf'])
logger.debug('Assigning %s from %s' % ('Mobility connector mAttachSize', 'mconfXML'))
mobilityConfig['mAttachSize'] = ds.xmlpath('.//settings/custom/attachmentMaxSize', XMLconfig['mconf'])
logger.debug('Assigning %s from %s' % ('Mobility connector dbMaintenance', 'mconfXML'))
mobilityConfig['dbMaintenance'] = ds.xmlpath('.//settings/custom/databaseMaintenance', XMLconfig['mconf'])
logger.debug('Assigning %s from %s' % ('Mobility log level', 'mconfXML'))
mobilityConfig['logLevel'] = ds.xmlpath('.//settings/common/log/level', XMLconfig['mconf'])

# GroupWise / SOAP values
logger.debug('Assigning %s from %s' % ('GroupWise log level', 'gconfXML'))
gwConfig['logLevel'] = ds.xmlpath('.//settings/common/log/level', XMLconfig['gconf'])
logger.debug('Assigning %s from %s' % ('GroupWise connector sListenAddress', 'gconfXML'))
gwConfig['sListenAddress'] = ds.xmlpath('.//settings/custom/listeningLocation', XMLconfig['gconf'])
logger.debug('Assigning %s from %s' % ('GroupWise connector gPort', 'gconfXML'))
gwConfig['gport'] = ds.xmlpath('.//settings/custom/port', XMLconfig['gconf'])
logger.debug('Assigning %s from %s' % ('GroupWise connector gAttachSize', 'gconfXML'))
gwConfig['gAttachSize'] = ds.xmlpath('.//settings/custom/attachmentMaxSize', XMLconfig['gconf'])
logger.debug('Assigning %s from %s' % ('GroupWise connector gListenAddress', 'gconfXML'))
if dsVersion >= ds_14x:
	gwConfig['gListenAddress'] = ds.xmlpath('.//settings/custom/soapServer', XMLconfig['gconf']).split(":")[0]
else:
	gwConfig['gListenAddress'] = ds.xmlpath('.//settings/custom/soapServer', XMLconfig['gconf']).split("://")[-1].split(":")[0]
logger.debug('Assigning %s from %s' % ('GroupWise connector sPort', 'gconfXML'))
gwConfig['sPort'] = ds.xmlpath('.//settings/custom/soapServer', XMLconfig['gconf']).split(":")[-1]
logger.debug('Assigning %s from %s' % ('GroupWise connector sSecure', 'gconfXML'))

if dsVersion >= ds_14x:
	logger.debug('Assigning %s from %s' % ('GroupWise connector POASecure', 'gconfXML'))
	gwConfig['POASecure'] = ds.xmlpath('.//settings/custom/sslPOAs', XMLconfig['gconf'])
	if gwConfig['POASecure'] == '0':
		gwConfig['sSecure'] = 'http'
	elif gwConfig['POASecure'] == '1':
		gwConfig['sSecure'] = 'https'
else:
	gwConfig['sSecure'] = ds.xmlpath('.//settings/custom/soapServer', XMLconfig['gconf']).split(":")[0]

# Trusted app values
logger.debug('Assigning %s from %s' % ('Trusted app name', 'gconfXML'))
trustedConfig['name'] = ds.xmlpath('.//settings/custom/trustedAppName', XMLconfig['gconf'])
logger.debug('Assigning %s from %s' % ('Trusted app key', 'gconfXML'))
trustedConfig['key'] = ds.getDecrypted('.//settings/custom/trustedAppKey',XMLconfig['gconf'], './/settings/custom/protected', force=forceMode)

logger.debug('Assigning %s from %s' % ('Web port', 'wconfXML'))
webConfig['port'] = ds.xmlpath('.//server/port', XMLconfig['wconf'])
logger.debug('Assigning %s from %s' % ('Web Listen IP', 'wconfXML'))
webConfig['ip'] = ds.xmlpath('.//server/ip', XMLconfig['wconf'])

time2 = time.time()
logger.info('Assigning variables from XML complete')
logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
# Stop spinner
spinner.stop(); print '\n'

# Test database connection
if not forceMode:
	if not ds.checkPostgresql(dbConfig):
		ds.eContinue()
		sys.exit(1)

##################################################################################################
#	Run later Switches
##################################################################################################
# Debug menu
if args.debugMenu:
	import dsapp_menus as dsMenu
	dsMenu.getConfigs(dbConfig, ldapConfig, mobilityConfig, gwConfig, trustedConfig, XMLconfig, config_files, webConfig, authConfig)
	dsMenu.debug_menu()
	sys.exit(0)

# Change db pass
if args.db:
	ds.changeDBPass(config_files, XMLconfig)
	ds.eContinue()
	sys.exit(0)

# Run health check
if args.ghc:
	import dsapp_ghc as ghc
	ghc.generalHealthCheck(mobilityConfig, gwConfig, XMLconfig ,ldapConfig, dbConfig, trustedConfig, config_files, webConfig)
	print; ds.eContinue()
	sys.exit(0)

# Get / upload mobility logs
if args.upload:
	ds.getLogs(mobilityConfig, gwConfig, XMLconfig ,ldapConfig, dbConfig, trustedConfig, config_files, webConfig)
	print; ds.eContinue()
	sys.exit(0)

# Run nightly maintenance
if args.check:
	print ds.checkNightlyMaintenance(config_files, mobilityConfig)['output']
	print; ds.eContinue()
	sys.exit(0)

# Show sync status
if args.status:
	ds.showStatus(dbConfig)
	print; ds.eContinue()
	sys.exit(0)

# Update mobility URL
if args.update:
	ds.updateMobilityFTP()
	ds.eContinue()
	sys.exit(0)

# Vacuum db
if args.vacuum:
	ds.rcDS('stop')
	ds.vacuumDB(dbConfig)
	if args.index:
		ds.indexDB(dbConfig)
	ds.rcDS('start')
	ds.eContinue()
	sys.exit(0)

# Index db
if args.index:
	ds.rcDS('stop')
	ds.indexDB(dbConfig)
	if args.vacuum:
		ds.vacuumDB(dbConfig)
	ds.rcDS('start')
	ds.eContinue()
	sys.exit(0)

# Show Users
if args.users:
	if args.devices:
		data = ds.getUsers_and_Devices(dbConfig, showBoth=True)
		count_out = "Number of users: %s\nCount of devices: %s\n" % (data['userCount'][0]['count'], data['deviceCount'][0]['count'])
	else:
		data = ds.getUsers_and_Devices(dbConfig, showUsers=True)
		count_out = "Number of users: %s\n" % data['userCount'][0]['count']

	out = ds.util_subprocess(data['cmd'])
	pydoc.pager(count_out + '\n' + out[0])
	sys.exit(0)

# Show Devices
if args.devices:
	if args.users:
		data = ds.getUsers_and_Devices(dbConfig, showBoth=True)
		count_out = "Number of users: %s\nCount of devices: %s\n" % (data['userCount'][0]['count'], data['deviceCount'][0]['count'])
	else:
		data = ds.getUsers_and_Devices(dbConfig, showDevices=True)
		count_out = "Number of devices: %s\n" % data['deviceCount'][0]['count']

	out = ds.util_subprocess(data['cmd'])
	pydoc.pager(count_out + '\n' + out[0])
	sys.exit(0)

# Load restore menu
if args.re == 'backup':
	import dsapp_re
	dsapp_re.dumpConfigs(dbConfig, ldapConfig, mobilityConfig, gwConfig, trustedConfig, config_files, webConfig, authConfig)
	print; ds.eContinue()
	sys.exit(0)

# Remove all encryption from XMLs
if args.clear:
	ds.clearTextEncryption(config_files, XMLconfig, ldapConfig, authConfig)
	sys.exit(0)

##################################################################################################
#	DEBUG
##################################################################################################

DEBUG_ENABLED = False
if DEBUG_ENABLED:
	pass

	sys.exit(0)

##################################################################################################
#	Main
##################################################################################################

if len(sys.argv) == 1 or args.force:
	import dsapp_menus as menus
	menus.getConfigs(dbConfig, ldapConfig, mobilityConfig, gwConfig, trustedConfig, XMLconfig, config_files, webConfig, authConfig)
	menus.main_menu()

sys.exit(0)
