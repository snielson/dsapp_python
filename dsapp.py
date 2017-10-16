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

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/lib')
import dsapp_global as glb
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

glb.initVersion() # dsapp version
glb.initFolders() # Folder variables
glb.initMobilityDirectory() # Mobility Directories
glb.initConfigFiles() # Configuration File
glb.initMiscSettings() # Misc variables
glb.initLogs() # Mobility logs
glb.initSystemLog() # System logs
glb.initDsappConfig() # dsapp Conf / Logs

# Create dsapp folder stucture
dsapp_folders = [glb.dsappDirectory, glb.dsappConf, glb.dsappLogs, glb.dsappBackup, glb.dsapptmp, glb.dsappupload, glb.rootDownloads, glb.dsapplib, glb.dsappdata]
for folder in dsapp_folders:
	if not os.path.exists(folder):
		os.makedirs(folder)

# Create setting.cfg if not found
if not os.path.isfile(glb.dsappSettings):
	dsHostname = os.popen('echo `hostname -f`').read().rstrip()
	with open(glb.dsappSettings, 'w') as cfgfile:
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
		Config.set('Misc', 'dsapp.version', glb.dsappversion)
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
Config.read(glb.dsappSettings)
if not Config.has_section('Upload Logs'): # Added v239
	Config.add_section('Upload Logs')
	Config.set('Upload Logs', 'mobility.agent', 3)
	Config.set('Upload Logs', 'mobility', 3)
	Config.set('Upload Logs', 'groupwise.agent', 3)
	Config.set('Upload Logs', 'groupwise', 3)
	Config.set('Upload Logs', 'messages', 2)
	Config.set('Upload Logs', 'postgres', 3)

with open(glb.dsappSettings, 'wb') as cfgfile:
	Config.write(cfgfile)


import dsapp_Definitions as ds

##################################################################################################
#	Log Settings
##################################################################################################

logging.config.fileConfig(glb.dsappLogSettings)
excep_logger = logging.getLogger('exceptions_log')
logger = logging.getLogger(__name__)
logger.info('------------- Starting dsapp v%s -------------' % glb.dsappversion)
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
	ds.removeAllFolders(glb.dsapptmp)
	ds.removeAllFiles(glb.dsapptmp)

	# Reset terminal (for blank text bug on Ctrl + C)
	os.system('stty sane')
	
	logger.info('------------- Exiting dsapp v%s -------------' % glb.dsappversion)

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
	glb.osVersion = int(ds.getOS_Version())
	logger.info("Detected SLES version %s" % glb.osVersion)
except:
	logger.warning("Unable to detect SLES version")


##################################################################################################
#	Check Switches
##################################################################################################
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--version', action='version', version='%(prog)s (version {version})'.format(version=glb.dsappversion))
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
parser.add_argument('-r', '--reinit', action='store_true', dest='reinit', help='Reinitialize all users')
parser.add_argument('-db', '--database', action='store_true', dest='db', help='Change database password')
parser.add_argument('-cl', '--clear', action='store_true', dest='clear', help='Remove encryption from XMLs')
parser.add_argument('--config', dest='re', choices=['backup', 'restore'], help='Backup settings or install Mobility with backup')
parser.add_argument('--setlog', dest='loglevel', choices=['debug','info','warning'], help='Set the logging level')
parser.add_argument('--debugMenu', action='store_true', dest='debugMenu', help='Show debug menu for dsapp')
args = parser.parse_args()
logger.debug("Switches: %s" % args)

if args.re == 'restore':
	logger.info("Running switch: restore")
	import dsapp_re
	dsapp_re.install_settings()
	print; ds.eContinue()
	sys.exit(0)

if args.bug:
	logger.info("Running switch: bug")
	ds.datasyncBanner()
	print "Report issues to: https://github.com/snielson/dsapp_python/issues\n"
	print "Useful logs can be located at:\n/opt/novell/datasync/tools/dsapp/logs/\nSet dsapp logs into debug for more information `dsapp --setlog debug`\n"
	print "Feel free to email %s directly at <%s>" % (__author__, __email__)
	sys.exit(0)

if args.dsUpdate:
	logger.info("Running switch: updateDsapp")
	ds.autoUpdateDsapp(True)
	ds.eContinue()
	sys.exit(0)

# Set logs if loglevel switch passed in
if args.loglevel:
	logger.info("Running switch: setlog")
	Config.read(glb.dsappLogSettings)
	Config.set('logger___main__', 'level', args.loglevel.upper())
	Config.set('logger_dsapp_Definitions', 'level', args.loglevel.upper())
	with open(glb.dsappLogSettings, 'wb') as logFile:
		Config.write(logFile)
	print "dsapp logs set to %s" % args.loglevel.upper()
	logger.info("dsapp logs set to %s" % args.loglevel.upper())
	sys.exit(0)

if args.autoUpdate:
	logger.info("Running switch: autoUpdate")
	Config.read(glb.dsappSettings)
	temp = Config.getboolean('Settings', 'auto.update')
	temp = not temp
	Config.set('Settings', 'auto.update', temp)
	with open(glb.dsappSettings, 'wb') as cfgfile:
		logger.debug("Writing: [Settings] auto.update = %s" % temp)
		Config.write(cfgfile)
	print ("Set auto update to '%s'" % temp)
	logger.info("Set auto update to '%s'" % temp)
	sys.exit(0)

# Check / set force mode
if args.force:
	logger.info("Running switch: force")
glb.forceMode = args.force

if args.clear or args.db:
	glb.forceMode = True

# Check if installed
if not ds.checkInstall():
	sys.exit(1)

# Give force mode warning
if glb.forceMode:
	if not args.re and not args.clear and not args.db:
		ds.datasyncBanner()
		print ("Running force mode. Some options may not work properly.\n")
		logger.warning('Running in force mode')
		ds.eContinue()

# Get mobility version
dsVersion = ds.getDSVersion()

# Debug logging: dsVersion
if dsVersion >= glb.ds_14x:
	logger.debug('Version : Mobility 14x')
elif dsVersion >= glb.ds_2x:
	logger.debug('Version : Mobility 2x')
elif dsVersion >= glb.ds_1x:
	logger.debug('Version : Mobility 1x')
		
# Update values in settings.cfg
Config.read(glb.dsappSettings)
Config.set('Misc', 'mobility.version', dsVersion)
Config.set('Misc', 'dsapp.version', glb.dsappversion)
Config.set('Misc', 'sles.version', glb.osVersion)
with open(glb.dsappSettings, 'wb') as cfgfile:
	logger.debug("Writing: [Misc] mobility.version = %s" % dsVersion)
	logger.debug("Writing: [Misc] dsapp.version = %s" % glb.dsappversion)
	logger.debug("Writing: [Misc] sles.version = %s" % glb.osVersion)
	Config.write(cfgfile)

# Assign variables based on settings.cfg
Config.read(glb.dsappSettings)
dsHostname = Config.get('Misc', 'hostname')

# Get Mobility Version
if not glb.forceMode:
	glb.mobilityVersion = ds.getVersion(ds.checkInstall())

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
glb.initDictonaries()

ds.datasyncBanner()

# Verify XML files
if not ds.check_XML(glb.config_files['mconf']):
	ds.dsappExitError("Problem with %s" % glb.config_files['mconf'], exit=True, printMessage=True, writeLog=False)
if not ds.check_XML(glb.config_files['econf']):
	ds.dsappExitError("Problem with %s" % glb.config_files['econf'], exit=True, printMessage=True, writeLog=False)
if not ds.check_XML(glb.config_files['ceconf']):
	ds.dsappExitError("Problem with %s" % glb.config_files['ceconf'], exit=True, printMessage=True, writeLog=False)
if not ds.check_XML(glb.config_files['wconf']):
	ds.dsappExitError("Problem with %s" % glb.config_files['wconf'], exit=True, printMessage=True, writeLog=False)
if not ds.check_XML(glb.config_files['gconf']):
	ds.dsappExitError("Problem with %s" % glb.config_files['gconf'], exit=True, printMessage=True, writeLog=False)

# XML tree of each XML file
logger.info('Building XML trees started')
time1 = time.time()
logger.debug('Building %s tree from: %s' % ('mconfXML', glb.config_files['mconf']))
glb.XMLconfig['mconf'] = ds.getXMLTree(glb.config_files['mconf'])
logger.debug('Building %s tree from: %s' % ('econfXML', glb.config_files['econf']))
glb.XMLconfig['econf'] = ds.getXMLTree(glb.config_files['econf'])
logger.debug('Building %s tree from: %s' % ('ceconfXML', glb.config_files['ceconf']))
glb.XMLconfig['ceconf'] = ds.getXMLTree(glb.config_files['ceconf'])
logger.debug('Building %s tree from: %s' % ('wconfXML', glb.config_files['wconf']))
glb.XMLconfig['wconf'] = ds.getXMLTree(glb.config_files['wconf'])
logger.debug('Building %s tree from: %s' % ('gconfXML', glb.config_files['gconf']))
glb.XMLconfig['gconf'] = ds.getXMLTree(glb.config_files['gconf'])
time2 = time.time()
logger.info('Building XML trees complete')
logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

# Check current hostname with stored hostname
if args.host:
	logger.info("Running switch: changeHost")
	print ("This should only be used if the hostname encryption is not detected by dsapp")
	if ds.askYesOrNo("Continue to fix encryption"):
		old_host = raw_input("Previous hostname: ")
		print
		ds.check_hostname(old_host, forceFix=True)
	print; sys.exit(0)

elif not args.host:
	logger.info('Checking hostname')
	if not ds.check_hostname(dsHostname):
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
glb.authConfig['provisioning'] = ds.xmlpath('.//configengine/source/provisioning', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('authentication', 'ceconfXML'))
glb.authConfig['authentication'] = ds.xmlpath('.//configengine/source/authentication', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('smtpPassword', 'ceconfXML'))
glb.authConfig['smtpPassword'] = ds.getDecrypted('.//configengine/notification/smtpPassword', glb.XMLconfig['ceconf'], './/configengine/notification/protected', force=glb.forceMode)

# LDAP values
logger.debug('Assigning %s from %s' % ('ldap secure', 'ceconfXML'))
glb.ldapConfig['secure'] = ds.xmlpath('.//configengine/ldap/secure', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('login', 'ceconfXML'))
glb.ldapConfig['login'] = ds.xmlpath('.//configengine/ldap/login/dn', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('password', 'ceconfXML'))
glb.ldapConfig['pass'] = ds.getDecrypted('.//configengine/ldap/login/password', glb.XMLconfig['ceconf'], './/configengine/ldap/login/protected', force=glb.forceMode)
glb.ldapConfig['enc_pass'] = ds.xmlpath('.//configengine/ldap/login/password', glb.XMLconfig['ceconf'])

logger.debug('Assigning %s from %s' % ('ldap enabled', 'ceconfXML'))
glb.ldapConfig['enabled'] = ds.xmlpath('.//configengine/ldap/enabled', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('LDAP group container', 'ceconfXML'))
glb.ldapConfig['group'] = ds.xmlpath_findall('.//configengine/ldap/groupContainer', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('LDAP user container', 'ceconfXML'))
glb.ldapConfig['user'] = ds.xmlpath_findall('.//configengine/ldap/userContainer', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('LDAP admins', 'ceconfXML'))
glb.ldapConfig['admins'] = ds.xmlpath_findall('.//configengine/ldap/admins/dn', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('LDAP port', 'ceconfXML'))
glb.ldapConfig['port'] = ds.xmlpath('.//configengine/ldap/port', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('LDAP host', 'ceconfXML'))
glb.ldapConfig['host'] = ds.xmlpath('.//configengine/ldap/hostname', glb.XMLconfig['ceconf'])

# Postgresql values
logger.debug('Assigning %s from %s' % ('Postgresql Username', 'ceconfXML'))
glb.dbConfig['user'] = ds.xmlpath('.//configengine/database/username', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('Postgresql Hostname', 'ceconfXML'))
glb.dbConfig['host'] = ds.xmlpath('.//configengine/database/hostname', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('Postgresql Port', 'ceconfXML'))
glb.dbConfig['port'] = ds.xmlpath('.//configengine/database/port', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('Postgresql Database', 'ceconfXML'))
glb.dbConfig['db'] = ds.xmlpath('.//configengine/database/db', glb.XMLconfig['ceconf'])
logger.debug('Assigning %s from %s' % ('Postgresql Password', 'ceconfXML'))
glb.dbConfig['pass'] = ds.getDecrypted('.//configengine/database/password', glb.XMLconfig['ceconf'], './/configengine/database/protected', force=glb.forceMode)

logger.debug('Assigning %s from %s' % ('Mobility connector mPort', 'mconfXML'))
glb.mobilityConfig['mPort'] = ds.xmlpath('.//settings/custom/listenPort', glb.XMLconfig['mconf'])
logger.debug('Assigning %s from %s' % ('Mobility connector mSecure', 'mconfXML'))
glb.mobilityConfig['mSecure'] = ds.xmlpath('.//settings/custom/ssl', glb.XMLconfig['mconf'])
logger.debug('Assigning %s from %s' % ('Mobility connector mlistenAddress', 'mconfXML'))
glb.mobilityConfig['mlistenAddress'] = ds.xmlpath('.//settings/custom/listenAddress', glb.XMLconfig['mconf'])
logger.debug('Assigning %s from %s' % ('Mobility connector galUserName', 'mconfXML'))
glb.mobilityConfig['galUserName'] = ds.xmlpath('.//settings/custom/galUserName', glb.XMLconfig['mconf'])
logger.debug('Assigning %s from %s' % ('Mobility connector mAttachSize', 'mconfXML'))
glb.mobilityConfig['mAttachSize'] = ds.xmlpath('.//settings/custom/attachmentMaxSize', glb.XMLconfig['mconf'])
logger.debug('Assigning %s from %s' % ('Mobility connector dbMaintenance', 'mconfXML'))
glb.mobilityConfig['dbMaintenance'] = ds.xmlpath('.//settings/custom/databaseMaintenance', glb.XMLconfig['mconf'])
logger.debug('Assigning %s from %s' % ('Mobility log level', 'mconfXML'))
glb.mobilityConfig['logLevel'] = ds.xmlpath('.//settings/common/log/level', glb.XMLconfig['mconf'])

# GroupWise / SOAP values
logger.debug('Assigning %s from %s' % ('GroupWise log level', 'gconfXML'))
glb.gwConfig['logLevel'] = ds.xmlpath('.//settings/common/log/level', glb.XMLconfig['gconf'])
logger.debug('Assigning %s from %s' % ('GroupWise connector sListenAddress', 'gconfXML'))
glb.gwConfig['sListenAddress'] = ds.xmlpath('.//settings/custom/listeningLocation', glb.XMLconfig['gconf'])
logger.debug('Assigning %s from %s' % ('GroupWise connector gPort', 'gconfXML'))
glb.gwConfig['gport'] = ds.xmlpath('.//settings/custom/port', glb.XMLconfig['gconf'])
logger.debug('Assigning %s from %s' % ('GroupWise connector gAttachSize', 'gconfXML'))
glb.gwConfig['gAttachSize'] = ds.xmlpath('.//settings/custom/attachmentMaxSize', glb.XMLconfig['gconf'])
logger.debug('Assigning %s from %s' % ('GroupWise connector gListenAddress', 'gconfXML'))
if dsVersion >= glb.ds_14x:
	glb.gwConfig['gListenAddress'] = ds.xmlpath('.//settings/custom/soapServer', glb.XMLconfig['gconf']).split(":")[0]
else:
	glb.gwConfig['gListenAddress'] = ds.xmlpath('.//settings/custom/soapServer', glb.XMLconfig['gconf']).split("://")[-1].split(":")[0]
logger.debug('Assigning %s from %s' % ('GroupWise connector sPort', 'gconfXML'))
glb.gwConfig['sPort'] = ds.xmlpath('.//settings/custom/soapServer', glb.XMLconfig['gconf']).split(":")[-1].split('/')[0]
logger.debug('Assigning %s from %s' % ('GroupWise connector sSecure', 'gconfXML'))

if dsVersion >= glb.ds_14x:
	logger.debug('Assigning %s from %s' % ('GroupWise connector POASecure', 'gconfXML'))
	glb.gwConfig['POASecure'] = ds.xmlpath('.//settings/custom/sslPOAs', glb.XMLconfig['gconf'])
	if glb.gwConfig['POASecure'] == '0':
		glb.gwConfig['sSecure'] = 'http'
	elif glb.gwConfig['POASecure'] == '1':
		glb.gwConfig['sSecure'] = 'https'
else:
	glb.gwConfig['sSecure'] = ds.xmlpath('.//settings/custom/soapServer', glb.XMLconfig['gconf']).split(":")[0]

# Trusted app values
logger.debug('Assigning %s from %s' % ('Trusted app name', 'gconfXML'))
glb.trustedConfig['name'] = ds.xmlpath('.//settings/custom/trustedAppName', glb.XMLconfig['gconf'])
logger.debug('Assigning %s from %s' % ('Trusted app key', 'gconfXML'))
glb.trustedConfig['key'] = ds.getDecrypted('.//settings/custom/trustedAppKey',glb.XMLconfig['gconf'], './/settings/custom/protected', force=glb.forceMode)

logger.debug('Assigning %s from %s' % ('Web port', 'wconfXML'))
glb.webConfig['port'] = ds.xmlpath('.//server/port', glb.XMLconfig['wconf'])
logger.debug('Assigning %s from %s' % ('Web Listen IP', 'wconfXML'))
glb.webConfig['ip'] = ds.xmlpath('.//server/ip', glb.XMLconfig['wconf'])

time2 = time.time()
logger.info('Assigning variables from XML complete')
logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
# Stop spinner
spinner.stop(); print '\n'

# Test database connection
if not glb.forceMode:
	if not ds.checkPostgresql():
		ds.eContinue()
		sys.exit(1)

##################################################################################################
#	Run later Switches
##################################################################################################
# Debug menu
if args.debugMenu:
	logger.info("Running switch: debugMenu")
	import dsapp_menus as dsMenu
	dsMenu.debug_menu()
	sys.exit(0)

# Change db pass
if args.db:
	logger.info("Running switch: database")
	ds.changeDBPass()
	ds.eContinue()
	sys.exit(0)

# Run health check
if args.ghc:
	logger.info("Running switch: gHealthCheck")
	import dsapp_ghc as ghc
	ghc.generalHealthCheck()
	print; ds.eContinue()
	sys.exit(0)

# Get / upload mobility logs
if args.upload:
	logger.info("Running switch: uploadLogs")
	ds.getLogs()
	print; ds.eContinue()
	sys.exit(0)

# Run nightly maintenance
if args.check:
	logger.info("Running switch: check")
	print ds.checkNightlyMaintenance()['output']
	print; ds.eContinue()
	sys.exit(0)

# Show sync status
if args.status:
	logger.info("Running switch: status")
	ds.showStatus()
	print; ds.eContinue()
	sys.exit(0)

# Update mobility URL
if args.update:
	logger.info("Running switch: update")
	ds.updateMobilityFTP()
	ds.eContinue()
	sys.exit(0)

# Vacuum db
if args.vacuum:
	logger.info("Running switch: vacuum")
	ds.rcDS('stop')
	ds.vacuumDB()
	if args.index:
		logger.info("Running switch: index")
		ds.indexDB()
	ds.rcDS('start')
	ds.eContinue()
	sys.exit(0)

# Index db
if args.index:
	logger.info("Running switch: index")
	ds.rcDS('stop')
	ds.indexDB()
	if args.vacuum:
		logger.info("Running switch: vacuum")
		ds.vacuumDB()
	ds.rcDS('start')
	ds.eContinue()
	sys.exit(0)

# Show Users
if args.users:
	logger.info("Running switch: users")
	if args.devices:
		logger.info("Running switch: devices")
		data = ds.getUsers_and_Devices(showBoth=True)
		count_out = "Number of users: %s\nCount of devices: %s\n" % (data['userCount'][0]['count'], data['deviceCount'][0]['count'])
	else:
		data = ds.getUsers_and_Devices(showUsers=True)
		count_out = "Number of users: %s\n" % data['userCount'][0]['count']

	out = ds.util_subprocess(data['cmd'])
	pydoc.pager(count_out + '\n' + out[0])
	sys.exit(0)

# Show Devices
if args.devices:
	logger.info("Running switch: devices")
	if args.users:
		logger.info("Running switch: users")
		data = ds.getUsers_and_Devices(showBoth=True)
		count_out = "Number of users: %s\nCount of devices: %s\n" % (data['userCount'][0]['count'], data['deviceCount'][0]['count'])
	else:
		data = ds.getUsers_and_Devices(showDevices=True)
		count_out = "Number of devices: %s\n" % data['deviceCount'][0]['count']

	out = ds.util_subprocess(data['cmd'])
	pydoc.pager(count_out + '\n' + out[0])
	sys.exit(0)

# Load restore menu
if args.re == 'backup':
	logger.info("Running switch: config")
	import dsapp_re
	dsapp_re.dumpConfigs()
	print; ds.eContinue()
	sys.exit(0)

# Remove all encryption from XMLs
if args.clear:
	logger.info("Running switch: clear")
	ds.clearTextEncryption()
	sys.exit(0)

# Reinit all users
if args.reinit:
	logger.info("Running switch: reinit")
	if ds.askYesOrNo("Reinitialize all users"):
		ds.reinitAllUsers(True)
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
	menus.main_menu()

sys.exit(0)
