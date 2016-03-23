# Written by Shane Nielson <snielson@projectuminfinitas.com>

from __future__ import print_function
import os
import sys
import datetime
import shutil
import traceback
import tarfile
import socket
import contextlib
import logging, logging.config
import cPickle as pickle
import dsapp_Definitions as ds
import ConfigParser
Config = ConfigParser.ConfigParser()


# Folder variables
dsappDirectory = "/opt/novell/datasync/tools/dsapp"
dsappdata = dsappDirectory + "/data"
dsappConf = dsappDirectory + "/conf"
dsapptmp = dsappDirectory + "/tmp"
dsappSettings = dsappConf + "/setting.cfg"
dirOptMobility = "/opt/novell/datasync"
dirEtcMobility = "/etc/datasync"
dirVarMobility = "/var/lib/datasync"

# Certificate path
mobCert = '/var/lib/datasync/device/mobility.pem'
webCert = '/var/lib/datasync/webadmin/server.pem'

# Misc variables
ds_1x= 1
ds_2x = 2
ds_14x = 14
installedConnector = "/etc/init.d/datasync-connectors"
ERROR_MSG = "\ndsapp has encountered an error. See dsapp.log for more details"

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (dsappConf))
logger = logging.getLogger('dsapp_Definitions')
excep_logger = logging.getLogger('exceptions_log')

def my_handler(type, value, tb):
	tmp = traceback.format_exception(type, value, tb)
	excep_logger.error("Uncaught exception:\n%s" % ''.join(tmp).strip())
	print (''.join(tmp).strip())

# Install exception handler
sys.excepthook = my_handler

# Read Config
Config.read(dsappSettings)
dsappversion = Config.get('Misc', 'dsapp.version')

# Configs from main script
dbConfig = None
ldapConfig = None
mobilityConfig = None
gwConfig = None
trustedConfig = None
XMLconfig = None
config_files = None
webConfig = None
authConfig = None

def tarSettings(path):
	backup_name = os.path.basename(path)

	# Tar up all files
	with contextlib.closing(tarfile.open("%s/%s.tgz" % (dsappdata, backup_name), "w:gz")) as tar:
		try:
			tar.add(path, arcname=backup_name)
		except OSError:
			logger.warning("No such directory: %s" % backup_name)
	logger.info("Created %s/%s.tgz" % (dsappdata, backup_name))

def dumpConfigs(dbConfig, ldapConfig, mobilityConfig, gwConfig, trustedConfig, config_files, webConfig, authConfig):
	ds.datasyncBanner(dsappversion)
	if not ds.askYesOrNo("Backup mobility configuration"):
		return

	DATE = datetime.datetime.now().strftime("%m.%d.%y-%s")

	# Create folder for backup data
	new_folder = dsappdata + '/mobility_backup-%s' % DATE
	if not os.path.exists(new_folder):
		os.makedirs(new_folder)
	print ("Dumping settings to %s" % new_folder)
	logger.info("Dumping settings to %s" % new_folder)

	dump_folder = new_folder + '/dumpSettings'
	if not os.path.exists(dump_folder):
		os.makedirs(dump_folder)

	# Dump dsapp settings
	with open(dump_folder + '/dbConfig.p', 'wb') as handle:
		pickle.dump(dbConfig, handle)
		logger.debug("Created %s/dbConfig.p" % dump_folder)

	with open(dump_folder + '/ldapConfig.p', 'wb') as handle:
		pickle.dump(ldapConfig, handle)
		logger.debug("Created %s/ldapConfig.p" % dump_folder)

	with open(dump_folder + '/mobilityConfig.p', 'wb') as handle:
		pickle.dump(mobilityConfig, handle)
		logger.debug("Created %s/mobilityConfig.p" % dump_folder)

	with open(dump_folder + '/gwConfig.p', 'wb') as handle:
		pickle.dump(gwConfig, handle)
		logger.debug("Created %s/gwConfig.p" % dump_folder)

	with open(dump_folder + '/trustedConfig.p', 'wb') as handle:
		pickle.dump(trustedConfig, handle)
		logger.debug("Created %s/trustedConfig.p" % dump_folder)

	with open(dump_folder + '/config_files.p', 'wb') as handle:
		pickle.dump(config_files, handle)
		logger.debug("Created %s/config_files.p" % dump_folder)

	with open(dump_folder + '/webConfig.p', 'wb') as handle:
		pickle.dump(webConfig, handle)
		logger.debug("Created %s/webConfig.p" % dump_folder)

	with open(dump_folder + '/authConfig.p', 'wb') as handle:
		pickle.dump(authConfig, handle)
		logger.debug("Created %s/authConfig.p" % dump_folder)

	# Dumping target, and membershipCache table
	skip_db = False
	for key in dbConfig:
		if dbConfig[key] is None:
			skip_db = True
	if not skip_db:
		print ("\nGetting database tables..")
		logger.info("Getting database tables..")
		sql_folder = new_folder + '/SQLsettings'
		if not os.path.exists(sql_folder):
			os.makedirs(sql_folder)
		ds.dumpTable(dbConfig, 'datasync', 'membershipCache', sql_folder)
		ds.dumpTable(dbConfig, 'datasync', 'targets', sql_folder)
	else:
		print ("\nUnable to dump database table..")
		logger.warning("Unable to dump database table..")

	# Dumping certificate
	print ("Getting mobility certificates..")
	logger.info("Getting mobility certificates..")
	cert_folder = new_folder + '/certificates/'
	if not os.path.exists(cert_folder):
		os.makedirs(cert_folder)
	shutil.copy(mobCert, cert_folder)
	shutil.copy(webCert, cert_folder)


	print ("Settings have been dumped")
	logger.info("Settings have been dumped")

	# Compress setting directory
	tarSettings(new_folder)

	# Remove setting folder
	shutil.rmtree(new_folder)


def readConfigs(backup_path):
	if backup_path is None:
		return

	dumpSettings = backup_path + '/dumpSettings'
	if not os.path.isdir(dumpSettings):
		print ("No backup setting")
		logger.error("No backup settings")
		return

	global dbConfig
	global ldapConfig
	global gwConfig
	global mobilityConfig
	global trustedConfig
	global config_files
	global webConfig
	global authConfig

	# Check for all pickle files
	missing_file = False
	all_files = [dumpSettings + "/dbConfig.p",
	dumpSettings + "/ldapConfig.p",
	dumpSettings + "/gwConfig.p",
	dumpSettings + "/mobilityConfig.p",
	dumpSettings + "/trustedConfig.p",
	dumpSettings + "/config_files.p",
	dumpSettings + "/webConfig.p",
	dumpSettings + "/authConfig.p"]
	for x in xrange(len(all_files)):
		if not os.path.isfile(all_files[x]):
			print ("Missing %s" % all_files[x])
			logger.debug("Missing %s" % all_files[x])
			missing_file = True
	if missing_file:
		return

	with open(dumpSettings + "/dbConfig.p", "rb") as handle:
		dbConfig = pickle.load(handle)

	with open(dumpSettings + "/ldapConfig.p", "rb") as handle:
		ldapConfig = pickle.load(handle)

	with open(dumpSettings + "/gwConfig.p", "rb") as handle:
		gwConfig = pickle.load(handle)

	with open(dumpSettings + "/mobilityConfig.p", "rb") as handle:
		mobilityConfig = pickle.load(handle)

	with open(dumpSettings + "/trustedConfig.p", "rb") as handle:
		trustedConfig = pickle.load(handle)

	with open(dumpSettings + "/config_files.p", "rb") as handle:
		config_files = pickle.load(handle)

	with open(dumpSettings + "/webConfig.p", "rb") as handle:
		webConfig = pickle.load(handle)

	with open(dumpSettings + "/authConfig.p", "rb") as handle:
		authConfig = pickle.load(handle)

def getConfig():
	backup_path = ds.autoCompleteInput("Path to mobility backup: ")
	if os.path.isfile(backup_path):
		return backup_path
	else:
		print ("Not a file '%s'" % backup_path) 
		logger.error("Not a file '%s'" % backup_path) 
		return None

def install_settings():
	# TODO : DEV : Prompt to continue
	print ("This feature is currently under development:\n\nTasks to complete:")
	print ("LDAP settings import\nCertificate check / import\nUsers and group import\n")
	if not ds.askYesOrNo("Continue with restore"):
		return

	ds.datasyncBanner(dsappversion)

	# Is mobility already installed? Return if YES
	if os.path.isfile(installedConnector):
		print ("Mobility already installed\nOnly use 'restore' to install Mobility from backup")
		logger.warning ("Mobility already installed")
		return

	setupDir = dirOptMobility + '/syncengine/connectors/mobility/cli'
	path = getConfig()
	if path is None:
		return

	fileName = ds.file_content(path)[0]
	ds.untar_file(path, extractPath=dsapptmp)
	readConfigs(dsapptmp + '/' + fileName)

	# Validate all needed variabes are NOT None
	missingAttribute = False
	if dbConfig['pass'] is None:
		print (ERROR_MSG) 
		logger.error("dbConfig['pass'] = None")
		missingAttribute = True
	if gwConfig['sListenAddress'] is None:
		print (ERROR_MSG) 
		logger.error("gwConfig['sListenAddress'] = None")
		missingAttribute = True
	if mobilityConfig['galUserName'] is None:
		print (ERROR_MSG) 
		logger.error("mobilityConfig['galUserName'] = None")
		missingAttribute = True
	if mobilityConfig['mPort'] is None:
		print (ERROR_MSG) 
		logger.error("mobilityConfig['mPort'] = None")
		missingAttribute = True
	if mobilityConfig['mSecure'] is None:
		print (ERROR_MSG) 
		logger.error("mobilityConfig['mSecure'] = None")
		missingAttribute = True
	if gwConfig['gport'] is None:
		print (ERROR_MSG) 
		logger.error("gwConfig['gport'] = None")
		missingAttribute = True
	if gwConfig['gListenAddress'] is None:
		print (ERROR_MSG) 
		logger.error("gwConfig['gListenAddress'] = None")
		missingAttribute = True
	if gwConfig['sPort'] is None:
		print (ERROR_MSG) 
		logger.error("gwConfig['sPort'] = None")
		missingAttribute = True
	if gwConfig['sSecure'] is None:
		print (ERROR_MSG) 
		logger.error("gwConfig['sSecure'] = None")
		missingAttribute = True
	if trustedConfig['name'] is None:
		print (ERROR_MSG) 
		logger.error("trustedConfig['name'] = None")
		missingAttribute = True
	if trustedConfig['key'] is None:
		print (ERROR_MSG) 
		logger.error("trustedConfig['key'] = None")
		missingAttribute = True
	if missingAttribute:
		return

	# Get local IP, and validate IP is NOT 127.0.0.1
	local_IP = socket.gethostbyname(socket.gethostname())
	logger.debug("Detected local address: %s" % local_IP)
	if '127.0.0' in local_IP:
		logger.warning("Detected address defaulted to localhost. Setting to 'None'")
		local_IP = None

	if local_IP is None:
		print ("Unable to detect server address")
		logger.warning("Unable to detect server address, or set to None")
		if ds.askYesOrNo("Manually enter server address"):
			local_IP = raw_input("Server address: ")
		else:
			return

	# Does local_IP match sListenAddress
	if local_IP != gwConfig['sListenAddress']:
		print ("\nSever address does not match stored backup address\nLocal: %s\nBackup: %s\n" % (local_IP, gwConfig['sListenAddress'])) 
		if not ds.askYesOrNo("Is detected local server address correct (%s)" % local_IP):
			if ds.askYesOrNo("Manually enter server address"):
				local_IP = raw_input("Server address: ")
			else:
				return
		if ds.askYesOrNo("Install with local server address (%s)" % local_IP):
			gwConfig['sListenAddress'] = local_IP
		else:
			if not ds.askYesOrNo("Install with backup address (%s)" % gwConfig['sListenAddress']):
				return

	# Create a trusted application key
	trustedKey = dsapptmp + '/' + fileName + '/trustedKey.key'
	with open(trustedKey, 'a') as key:
		key.write(trustedConfig['key'])
		logger.info("Created trusted key at: %s" % trustedKey)

	# Get path / file
	isoPath = ds.getMobilityISO()

	# Verify ISO is mobility iso
	if not ds.checkISO_content(isoPath):
		return

	# Prompt to run install
	ds.datasyncBanner(dsappversion)
	print ("Mobility Backup: %s" % fileName)
	print ("Mobility ISO: %s" % os.path.basename(isoPath))
	if not ds.askYesOrNo("Install with settings"):
		return

	# All checks paasses - Add isoPath as 'mobility' repo
	print ("\nSetting up mobility repository..")
	logger.info("Setting up mobility repository")
	cmd = "zypper rr mobility"
	out = ds.util_subprocess(cmd, True)

	cmd = "zypper addrepo 'iso:///?iso=%s&url=file://%s' mobility" % (os.path.basename(isoPath), os.path.dirname(isoPath))
	out = ds.util_subprocess(cmd, True)

	# Refresh Repo
	print ("Refreshing mobility repository")
	logger.info("Refreshing mobility repository")
	cmd = "zypper --gpg-auto-import-keys ref -f mobility"
	out = ds.util_subprocess(cmd, True)

	# Install mobility pattern
	cmd = "zypper -x pt --repo mobility"
	out = ds.util_subprocess(cmd, True)
	try:
		patternName = out[0].split('pattern name=')[1].split('"')[1]
		logger.debug("Found Mobility pattern: %s" % patternName)
	except:
		print ("Unable to find Mobility pattern")
		logger.error("Unable to find Mobility pattern")
		return

	print ("Installing Mobility pattern: %s" % patternName)
	logger.info("Installing Mobility pattern: %s" % patternName)
	cmd = "zypper --non-interactive install -t pattern %s" % patternName
	out = ds.util_subprocess(cmd, True)

	# Get version of GMS installed
	if gwConfig['sSecure'] == 'https':
		gwConfig['sSecure'] = 'yes'
	elif gwConfig['sSecure'] == 'http':
		gwConfig['sSecure'] = 'no'

	# Swtich msecure 1 or 0 to true or false
	if bool(mobilityConfig['mSecure']):
		mobilityConfig['mSecure'] = 'true'
	else:
		mobilityConfig['mSecure'] = 'false'

	# Create variables for gms installs
	setup_one = "sh " + setupDir + "/postgres_setup_1.sh"
	setup_two = "python " + setupDir + "/odbc_setup_2.pyc"
	setup_three = "python " + setupDir + "/mobility_setup_3.pyc --provision 'groupwise' --dbpass '%s'" % dbConfig['pass']
	setup_four = "sh " + setupDir + "/enable_setup_4.sh"
	setup_five = "python " + setupDir + "/mobility_setup_5.pyc --provision 'groupwise' --galuser '%(galUserName)s' --block false --selfsigned true --path '' --lport '%(mPort)s' --secure %(mSecure)s" % mobilityConfig
	setup_six = "python " + setupDir + "/groupwise_setup_6.pyc --keypath '%s' --lport '%s' --lip '%s' --version '802' --soap %s --key '%s' --sport %s --psecure '%s'" % (trustedKey, gwConfig['gport'], gwConfig['sListenAddress'], gwConfig['gListenAddress'], trustedConfig['name'], gwConfig['sPort'], gwConfig['sSecure'])
	setup_seven = "python " + setupDir + "/start_mobility.pyc"

	# Run through install with all setups
	print ("\nConfiguring and extending database..")
	logger.info("Configuring and extending database..")
	out = ds.util_subprocess(setup_one, True)
	out = ds.util_subprocess(setup_two, True)

	print ("Configuring GroupWise Mobility Service..")
	logger.info("Configuring GroupWise Mobility Service..")
	out = ds.util_subprocess(setup_three, True)

	print ("Enabling and Starting GroupWise Mobility Service..")
	logger.info("Enabling and Starting GroupWise Mobility Service..")
	out = ds.util_subprocess(setup_four, True)

	print ("Configuring Device Sync Agent..")
	logger.info("Configuring Device Sync Agent..")
	out = ds.util_subprocess(setup_five, True)

	print ("Configuring GroupWise Sync Agent..")
	logger.info("Configuring GroupWise Sync Agent..")
	out = ds.util_subprocess(setup_six, True)

	print ("Starting Sync Agents..")
	logger.info("Starting Sync Agents..")
	out = ds.util_subprocess(setup_seven, True)

	# Prompt to match backup ldap settings
	if ldapConfig['enabled'] == 'true':
		if ds.askYesOrNo("Restore LDAP settings"):
			pass # TODO

	# Prompt for users and group to be imported
	if ds.askYesOrNo("Restore users and groups"):
		pass # TODO

	# TODO : Check current hostname, and validate if backup certificates common name will work on new server
	# Pass warning if common name != install hostname

	# Prompt for backup certs to be applied
	if ds.askYesOrNo("Restore backup certificates"):
		pass # TODO
