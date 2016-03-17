# Written by Shane Nielson <snielson@projectuminfinitas.com>

import sys
import os
import traceback
import dsapp_Definitions as ds
import logging, logging.config
import ConfigParser
Config = ConfigParser.ConfigParser()
import getch
getch = getch._Getch()
import textwrap
import subprocess

import dsapp_ghc as ghc
import dsapp_Soap as dsSOAP

COMPANY_BU = 'Novell'
# DISCLAIMER = "Use at your own discretion. dsapp is not supported by %s\n     See [dsapp --bug] to report issues" % COMPANY_BU
DISCLAIMER = "%s accepts no liability for the consequences of any actions taken\n     by the use of this application. Use at your own discretion" % COMPANY_BU

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
dsappSettings = dsappConf + "/setting.cfg"

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (dsappConf))
logger = logging.getLogger('__main__')
excep_logger = logging.getLogger('exceptions_log')

def my_handler(type, value, tb):
	tmp = traceback.format_exception(type, value, tb)
	excep_logger.error("Uncaught exception:\n%s" % ''.join(tmp).strip())
	print ''.join(tmp).strip()

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

def getConfigs(db, ldap, mobility, gw, trustedapp, xml, conf_files, web, auth):
	global dbConfig
	global ldapConfig
	global gwConfig
	global mobilityConfig
	global trustedConfig
	global XMLconfig
	global config_files
	global webConfig
	global authConfig

	dbConfig = db
	ldapConfig = ldap
	mobilityConfig = mobility
	gwConfig = gw
	trustedConfig = trustedapp
	XMLconfig = xml
	config_files = conf_files
	webConfig = web
	authConfig = auth

def show_menu(menu_call):
	ds.datasyncBanner(dsappversion)

	for i in xrange(len(menu_call)):
		print "     %s" % menu_call[i]

def test_out():
	print "This was selected."

def get_choice(available, special=None):
	print "\n     Selection: ",
	while True:
		choice = getch()
		if special is not None and choice == special:
			print
			return special
		elif choice in available or choice == 'q':
			if choice == '0' or choice == 'q':
				print
				return '0'
			else:
				print
				return choice

def build_avaialbe(menu):
	available = []
	for i in range(len(menu)):
		available.append('%s' % i)
	return available


##################################################################################################
#	Menus
##################################################################################################

def main_menu():
	menu = ['1. Logs', '2. Register & Update', '3. Database', '4. Certificates', '\n     5. User Issues', '6. User Info', '7. Checks & Queries', '\n     0. Quit']
	sub_menus = {'1': log_menu,'2': registerUpdate_menu, '3': database_menu, '4': certificate_menu, '5': userIssue_menu, '6': userInfo_menu, '7': checksQueries_menu}
	
	available = build_avaialbe(menu)
	show_menu(menu)

	# Print disclaimer
	ds.print_there(23,6, DISCLAIMER)
	
	choice = get_choice(available, 'd')
	if choice == '0':
		loop = False
		ds.clear()
		return
	elif choice == 'd':
		cmd = "PGPASSWORD=%(pass)s psql -U %(user)s datasync" % dbConfig
		ds.clear()
		subprocess.call(cmd, shell=True)
	else:
		sub_menus[choice]()


## Sub menus ##

def log_menu():
	menu = ['1. Upload logs','2. Remove log archives', '\n     0. Back']
	
	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.getLogs(mobilityConfig, gwConfig, XMLconfig ,ldapConfig, dbConfig, trustedConfig, config_files, webConfig)
			print; ds.eContinue()
		elif choice == '2':
			ds.cleanLog()
			print; ds.eContinue()
		elif choice == '0':
			loop = False
			main_menu()

def registerUpdate_menu():
	menu = ['1. Register Mobility', '2. Update Mobility', '3. FTF options...', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.datasyncBanner(dsappversion)
			ds.registerDS()
			print; ds.eContinue()
		elif choice == '2':
			update_menu()
		elif choice == '3':
			ftf_menu()
		elif choice == '0':
			loop = False
			main_menu()

### Start ### Sub menu for FTF
def ftf_menu():
	menu = ['1. Show applied FTFs','2. Apply FTFs', '\n     0. Back']
	
	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.showAppliedPatches()
			ds.eContinue()
		elif choice == '2':
			ds.datasyncBanner(dsappversion)

			Config.read(dsappSettings)
			serviceCheck = Config.get('FTF URL', 'check.service.address')
			serviceCheckPort = Config.getint('FTF URL', 'check.service.port')
			dlPath = Config.get('FTF URL', 'download.address')
			if ds.DoesServiceExist(serviceCheck, serviceCheckPort):
				# Get latest FTFlist.txt file
				FTFfile = dsappConf + '/dsapp_FTFlist.txt'
				if os.path.isfile(FTFfile):
					os.rename(FTFfile, FTFfile + '.bak')

				if not ds.dlfile('%sdsapp_FTFlist.txt' % dlPath, dsappConf, False, False):
					if os.path.isfile(FTFfile + '.bak'):
						os.rename(FTFfile + '.bak', FTFfile)

				if os.path.isfile(FTFfile):
					patches = ds.buildFTFPatchList(FTFfile)
					ds.selectFTFPatch(patches)
				else:
					print "No FTFs / Patches available"
					print; ds.eContinue()
			else:
				print "FTFs / Patches require FTF access to download"
				print; ds.eContinue()
		elif choice == '0':
			loop = False
			return
### End ### Sub menu for FTF

### Start ### Sub menu for Update Mobility (registerUpdate_menu) ###
def update_menu():
	menu = ['1. Update via Local ISO', '2. Update via URL', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.updateMobilityISO()
			ds.eContinue()
		elif choice == '2':
			ds.updateMobilityFTP()
			ds.eContinue()
		elif choice == '0':
			loop = False
			return
### End ### Sub menu for Update Mobility (registerUpdate_menu) ###

def database_menu():
	ds.datasyncBanner(dsappversion)
	print "The database menu will require Mobility to be stopped"
	if ds.askYesOrNo("Stop Mobility now"):
		ds.datasyncBanner(dsappversion)
		ds.rcDS('stop')
		menu = ['1. Vacuum Databases', '2. Re-Index Databases', '\n     3. Back up Databases', '4. Restore Databases', '\n     5. Recreate Global Address Book (GAL)', '6. Fix targets/membershipCache', '\n     7. CUSO Clean-Up Start-Over', '\n     0. Back -- Start Mobility']

		available = build_avaialbe(menu)
		loop = True
		while loop:
			show_menu(menu)
			choice = get_choice(available)
			if choice == '1':
				ds.datasyncBanner(dsappversion)
				print textwrap.fill("The amount of time this takes can vary depending on the last time it was completed. It is recommended that this be run every 6 months.", 80)
				print
				if ds.askYesOrNo("Do you want to continue"):
					ds.vacuumDB(dbConfig)
					print
					ds.eContinue()
			elif choice == '2':
				ds.datasyncBanner(dsappversion)
				print textwrap.fill("The amount of time this takes can vary depending on the last time it was completed. It is recommended that this be run after a database vacuum.", 80)
				print
				if ds.askYesOrNo("Do you want to continue"):
					ds.indexDB(dbConfig)
					print
					ds.eContinue()
			elif choice == '3':
				ds.backupDatabase(dbConfig)
				print; ds.eContinue()
			elif choice == '4':
				ds.restoreDatabase(dbConfig)
				print; ds.eContinue()
			elif choice == '5':
				ds.fix_gal(dbConfig)
				print; ds.eContinue()
			elif choice == '6':
				ds.addGroup(dbConfig, ldapConfig)
				print; ds.eContinue()
			elif choice == '7':
				cuso_menu()
			elif choice == '0':
				loop = False
				ds.datasyncBanner(dsappversion)
				ds.rcDS('start')
				main_menu()
	else:
		main_menu()

### Start ### Sub menu for database_menu ###
def cuso_menu():
	menu = ['1. Clean up and start over (Except Users)', '2. Clean up and start over (Everything)', '\n     3. Uninstall Mobility', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.datasyncBanner(dsappversion)
			if ds.askYesOrNo("Clean up and start over (Except Users)"):
				ds.cuso(dbConfig, 'user')
				print; ds.eContinue()
		elif choice == '2':
			ds.datasyncBanner(dsappversion)
			if ds.askYesOrNo("Clean up and start over (Everything)"):
				ds.cuso(dbConfig, 'everything')
				print; ds.eContinue()
		elif choice == '3':
			ds.datasyncBanner(dsappversion)
			print "Please run 'sh /opt/novell/datasync/uninstall.sh' first"
			if ds.askYesOrNo("Uninstall Mobility"):
				ds.cuso(dbConfig, 'uninstall')
		elif choice == '0':
			loop = False
			return
### End ### Sub menu for database_menu ###

def certificate_menu():
	menu = ['1. Generate self-signed certificate', '\n     2. Create CSR & Private key', '3. Install certificate from 3rd party', '\n     4. Verify certificate / key pair', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.createCSRKey(True)
			print; ds.eContinue()
		elif choice == '2':
			ds.createCSRKey()
			print; ds.eContinue()
		elif choice == '3':
			ds.createPEM()
			print; ds.eContinue()
		elif choice == '4':
			ds.verifyCertifiateMatch()
			print; ds.eContinue()
		elif choice == '0':
			loop = False
			main_menu()

def userIssue_menu():
	# menu = ['1. Monitor user sync options...', '2. GroupWise checks options...', '3. Remove & reinitialize users options...', '\n     4. User authentication issues', '5. Change user application name', '6. Change user FDN', '7. What deleted this (contact, email, folder, calendar)?', '8. List subjects of deleted items from device', '\n     0. Back']
	menu = ['1. Monitor user sync options...', '2. GroupWise checks options...', '3. Remove & reinitialize users options...', '\n     4. User authentication issues', '5. Change user application name', '6. Change user FDN', '7. What deleted this (contact, email, folder, calendar)?', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			monitorUser_menu()
		elif choice == '2':
			groupwiseChecks_menu()
		elif choice == '3':
			removeUser_menu()
		elif choice == '4':
			ds.check_userAuth(dbConfig, authConfig)
		elif choice == '5':
			ds.changeAppName(dbConfig)
		elif choice == '6':
			ds.updateFDN(dbConfig, XMLconfig, ldapConfig)
		elif choice == '7':
			ds.whereDidIComeFromAndWhereAmIGoingOrWhatHappenedToMe(dbConfig)
		elif choice == '8':
			pass
		elif choice == '0':
			loop = False
			main_menu()

### Start ### Sub menus userIssue_menu ###
def monitorUser_menu():
	menu = ['1. Monitor user sync state (Mobility)', '2. Monitor user sync GW/MC count (Sync-Validate)', '3. Monitor active users sync state', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.monitorUser(dbConfig)
		elif choice == '2':
			ds.monitor_Sync_validate(dbConfig)
		elif choice == '3':
			ds.monitor_syncing_users(dbConfig)
		elif choice == '0':
			loop = False
			return

def groupwiseChecks_menu():
	menu = ['1. Check user over SOAP', '2. Check GroupWise folder structure', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			userConfig = ds.verifyUser(dbConfig)
			if userConfig['name'] != None:
				if userConfig['type'] != 'group':
					dsSOAP.soap_printUser(trustedConfig, gwConfig, userConfig)
				else:
					print ("Input '%(name)s' is not a user. Type='%(type)s'" % userConfig)
				print; ds.eContinue()
		elif choice == '2':
			dsSOAP.soap_checkFolderList(trustedConfig, gwConfig, ds.verifyUser(dbConfig))
		elif choice == '0':
			loop = False
			return

def removeUser_menu():
	menu = ['1. Force remove user/group db references', '2. Remove user/group (restarts configengine)', '3. Remove disabled users & fix referenceCount', '\n     4. Reinitialize user', '5. Reinitialize all failed users', '6. Reinitialize all users', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.remove_user(dbConfig, 1)
		elif choice == '2':
			ds.remove_user(dbConfig)
		elif choice == '3':
			ds.datasyncBanner(dsappversion)
			ds.removed_disabled(dbConfig)
			print
			ds.fix_referenceCount(dbConfig)
			print; ds.eContinue()
		elif choice == '4':
			ds.setUserState(dbConfig, '7')
		elif choice == '5':
			ds.reinitAllFailedUsers(dbConfig)
			print;ds.eContinue()
		elif choice == '6':
			ds.reinitAllUsers(dbConfig)
			print;ds.eContinue()
		elif choice == '0':
			loop = False
			return
### End ### Sub menus userIssue_menu ###

def userInfo_menu():
	menu = ['1. List all devices from db', '2. List of GMS users & emails', '3. List user PAB content', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.list_deviceInfo(dbConfig)
			ds.eContinue()
		elif choice == '2':
			ds.list_usersAndEmails(dbConfig)
			ds.eContinue()
		elif choice == '3':
			ds.getUserPAB(dbConfig)
		elif choice == '0':
			loop = False
			main_menu()

def checksQueries_menu():
	menu = ['1. General Health Check (beta)', '2. Nightly Maintenance Check', '\n     3. Show Sync Status', '4. GW pending events by User (consumerevents)', '5. Mobility pending events by User (syncevents)', '\n     6. Attachments...', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ghc.generalHealthCheck(mobilityConfig, gwConfig, XMLconfig ,ldapConfig, dbConfig, trustedConfig, config_files, webConfig)
			print; ds.eContinue()
		elif choice == '2':
			print ds.checkNightlyMaintenance(config_files, mobilityConfig)['output']
			print; ds.eContinue()
		elif choice == '3':
			ds.datasyncBanner(dsappversion)
			ds.showStatus(dbConfig)
			print; ds.eContinue()
		elif choice == '4':
			ds.show_GW_syncEvents(dbConfig)
			print; ds.eContinue()
		elif choice == '5':
			ds.show_Mob_syncEvents(dbConfig)
			ds.eContinue()
		elif choice == '6':
			viewAttachments_menu()
		elif choice == '0':
			loop = False
			main_menu()

### Start ### Sub menus checkQueries_menu ###
def viewAttachments_menu():
	menu = ['1. View attachments by user', '2. Check Mobility attachments count', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.view_attach_byUser(dbConfig)
			ds.eContinue()
		elif choice == '2':
			ds.check_mob_attachments(dbConfig)
			print; ds.eContinue()
		elif choice == '0':
			loop = False
			return
### End ### Sub menus checkQueries_menu ###