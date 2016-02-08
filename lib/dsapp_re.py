# Written by Shane Nielson <snielson@projectuminfinitas.com>

from __future__ import print_function
import os
import sys
import datetime
import shutil
import tarfile
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

# Certificate path
mobCert = '/var/lib/datasync/device/mobility.pem'
webCert = '/var/lib/datasync/webadmin/server.pem'

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (dsappConf))
logger = logging.getLogger('dsapp_Definitions')

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
	new_folder = dsappdata + '/backup-%s' % DATE
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

	# DEV # TODO : Remove
	print ("\nFeature Work in progress.. ")

def getConfig():
	backup_path = ds.autoCompleteInput("Path to mobility backup: ")
	if os.path.isfile(backup_path):
		return backup_path
	else:
		print ("Not a file '%s'" % backup_path) 
		logger.error("Not a file '%s'" % backup_path) 
		return None

def install_settings():
	ds.datasyncBanner(dsappversion)
	path = getConfig()
	if path is None:
		return

	fileName = ds.file_content(path)[0]
	ds.untar_file(path, extractPath=dsapptmp)
	readConfigs(dsapptmp + '/' + fileName)


def call_re(dbConfig, ldapConfig, mobilityConfig, gwConfig, trustedConfig, config_files, webConfig, authConfig):
	import dsapp_menus as menu
	menu.re_menu(dbConfig, ldapConfig, mobilityConfig, gwConfig, trustedConfig, config_files, webConfig, authConfig)