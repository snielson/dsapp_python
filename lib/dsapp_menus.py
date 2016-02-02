<<<<<<< HEAD
# Written by Shane Nielson <snielson@projectuminfinitas.com>

=======
>>>>>>> origin/Development
import sys
import os
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

<<<<<<< HEAD
COMPANY_BU = 'Novell'
# DISCLAIMER = "Use at your own discretion. dsapp is not supported by %s\n     See [dsapp --bug] to report issues" % COMPANY_BU
DISCLAIMER = "%s accepts no liability for the consequences of any actions taken\n     by the use of this application. Use at your own discretion" % COMPANY_BU

=======
>>>>>>> origin/Development
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
<<<<<<< HEAD
webConfig = None
authConfig = None

def getConfigs(db, ldap, mobility, gw, trustedapp, xml, conf_files, web, auth):
=======

def getConfigs(db, ldap, mobility, gw, trustedapp, xml, conf_files):
>>>>>>> origin/Development
	global dbConfig
	global ldapConfig
	global gwConfig
	global mobilityConfig
	global trustedConfig
	global XMLconfig
	global config_files
<<<<<<< HEAD
	global webConfig
	global authConfig
=======
>>>>>>> origin/Development

	dbConfig = db
	ldapConfig = ldap
	mobilityConfig = mobility
	gwConfig = gw
	trustedConfig = trustedapp
	XMLconfig = xml
	config_files = conf_files
<<<<<<< HEAD
	webConfig = web
	authConfig = auth
=======
>>>>>>> origin/Development

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
<<<<<<< HEAD

	# Print disclaimer
	ds.print_there(23,6, DISCLAIMER)
	
=======
>>>>>>> origin/Development
	choice = get_choice(available, 'd')
	if choice == '0':
		loop = False
		return
	elif choice == 'd':
		cmd = "PGPASSWORD=%(pass)s psql -U %(user)s datasync" % dbConfig
		ds.clear()
		subprocess.call(cmd, shell=True)
	else:
		sub_menus[choice]()


## Sub menus ##

def log_menu():
<<<<<<< HEAD
	menu = ['1. Upload logs','2. Remove log archives', '\n     0. Back']
=======
	menu = ['1. Upload logs', '2. Set logs to defaults', '3. Set logs to diagnostics/debug', '4. Log Capture', '\n     5. Remove log archives', '\n     0. Back']
>>>>>>> origin/Development
	
	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
<<<<<<< HEAD
			ds.getLogs(mobilityConfig, gwConfig, XMLconfig ,ldapConfig, dbConfig, trustedConfig, config_files, webConfig)
			print; ds.eContinue()
		elif choice == '2':
			ds.cleanLog()
			print; ds.eContinue()
=======
			pass
		elif choice == '2':
			pass
		elif choice == '3':
			pass
		elif choice == '4':
			pass
		elif choice == '5':
			pass
>>>>>>> origin/Development
		elif choice == '0':
			loop = False
			main_menu()

def registerUpdate_menu():
	menu = ['1. Register Mobility', '2. Update Mobility', '3. Apply FTF / Patch Files', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
<<<<<<< HEAD
			ds.datasyncBanner(dsappversion)
			ds.registerDS()
			print; ds.eContinue()
=======
			pass
>>>>>>> origin/Development
		elif choice == '2':
			update_menu()
		elif choice == '3':
			ds.datasyncBanner(dsappversion)
<<<<<<< HEAD

			Config.read(dsappSettings)
			serviceCheck = Config.get('URL', 'ftf.check.service')
			dlPath = Config.get('URL', 'ftf.download.address')
			if ds.DoesServiceExist(serviceCheck, 21):
=======
			if ds.DoesServiceExist('ftp.novell.com', 21):
>>>>>>> origin/Development
				# Get latest FTFlist.txt file
				FTFfile = dsappConf + '/dsapp_FTFlist.txt'
				if os.path.isfile(FTFfile):
					os.rename(FTFfile, FTFfile + '.bak')

<<<<<<< HEAD
				if not ds.dlfile('%sdsapp_FTFlist.txt' % dlPath, dsappConf, False, False):
=======
				if not ds.dlfile('ftp://ftp.novell.com/outgoing/dsapp_FTFlist.txt', dsappConf, False, False):
>>>>>>> origin/Development
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
			main_menu()

### Start ### Sub menu for Update Mobility (registerUpdate_menu) ###
def update_menu():
<<<<<<< HEAD
	menu = ['1. Update via Local ISO', '2. Update via URL', '\n     0. Back']
=======
	menu = ['1. Update with Novell Update Channel', '2. Update with Local ISO', '3. Update with Novell FTP', '\n     0. Back']
>>>>>>> origin/Development

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
<<<<<<< HEAD
			ds.updateMobilityISO()
			ds.eContinue()
		elif choice == '2':
			ds.updateMobilityFTP()
			ds.eContinue()
=======
			pass
		elif choice == '2':
			pass
		elif choice == '3':
			ds.updateMobilityFTP()
>>>>>>> origin/Development
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
<<<<<<< HEAD
				ds.fix_gal(dbConfig)
				print; ds.eContinue()
			elif choice == '6':
				ds.addGroup(dbConfig, ldapConfig)
				print; ds.eContinue()
=======
				pass
			elif choice == '6':
				pass
>>>>>>> origin/Development
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
<<<<<<< HEAD
	# menu = ['1. Monitor user sync options...', '2. GroupWise checks options...', '3. Remove & reinitialize users options...', '\n     4. User authentication issues', '5. Change user application name', '6. Change user FDN', '7. What deleted this (contact, email, folder, calendar)?', '8. List subjects of deleted items from device', '\n     0. Back']
	menu = ['1. Monitor user sync options...', '2. GroupWise checks options...', '3. Remove & reinitialize users options...', '\n     4. User authentication issues', '5. Change user application name', '6. Change user FDN', '7. What deleted this (contact, email, folder, calendar)?', '\n     0. Back']
=======
	menu = ['1. Monitor user sync options...', '2. GroupWise checks options...', '3. Remove & reinitialize users options...', '\n     4. User authentication issues', '5. Change user application name', '6. Change user FDN', '7. What deleted this (contact, email, folder, calendar)?', '8. List subjects of deleted items from device', '\n     0. Back']
>>>>>>> origin/Development

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
<<<<<<< HEAD
			ds.check_userAuth(dbConfig, authConfig)
			ds.eContinue()
		elif choice == '5':
			ds.changeAppName(dbConfig)
			print; ds.eContinue()
=======
			pass
		elif choice == '5':
			pass
>>>>>>> origin/Development
		elif choice == '6':
			ds.updateFDN(dbConfig, XMLconfig, ldapConfig)
			print; ds.eContinue()
		elif choice == '7':
<<<<<<< HEAD
			ds.whereDidIComeFromAndWhereAmIGoingOrWhatHappenedToMe(dbConfig)
=======
			pass
>>>>>>> origin/Development
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
<<<<<<< HEAD
			ds.monitor_Sync_validate(dbConfig)
			print; ds.eContinue()
=======
			pass
>>>>>>> origin/Development
		elif choice == '3':
			ds.monitor_syncing_users(dbConfig)
		elif choice == '0':
			loop = False
			return

def groupwiseChecks_menu():
<<<<<<< HEAD
	menu = ['1. Check user over SOAP', '2. Check GroupWise folder structure', '\n     0. Back']
=======
	menu = ['1. Check user over SOAP', '2. Check GroupWise folder structure', '3. Remote GWcheck DELDUPFOLDERS (beta)', '\n     0. Back']
>>>>>>> origin/Development

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			userConfig = ds.verifyUser(dbConfig)
			if userConfig['name'] != None:
				dsSOAP.soap_printUser(trustedConfig, gwConfig, userConfig)
<<<<<<< HEAD
				print; ds.eContinue()
		elif choice == '2':
			dsSOAP.soap_checkFolderList(trustedConfig, gwConfig, ds.verifyUser(dbConfig))
			print; ds.eContinue()
=======
				print
				ds.eContinue()
		elif choice == '2':
			dsSOAP.soap_checkFolderList(trustedConfig, gwConfig, ds.verifyUser(dbConfig))
			print
			ds.eContinue()
		elif choice == '3':
			pass
>>>>>>> origin/Development
		elif choice == '0':
			loop = False
			return

def removeUser_menu():
	menu = ['1. Force remove user/group db references', '2. Remove user/group (restarts configengine)', '3. Remove disabled users & fix referenceCount', '\n     4. Reinitialize user (WebAdmin is recommended)', '5. Reinitialize all users (CAUTION - down time)', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.remove_user(dbConfig, 1)
<<<<<<< HEAD
			print; ds.eContinue()
		elif choice == '2':
			ds.remove_user(dbConfig)
			print; ds.eContinue()
		elif choice == '3':
			ds.datasyncBanner(dsappversion)
			ds.removed_disabled(dbConfig)
			print
			ds.fix_referenceCount(dbConfig)
			print; ds.eContinue()
=======
			print
			ds.eContinue()
		elif choice == '2':
			ds.remove_user(dbConfig)
			print
			ds.eContinue()
		elif choice == '3':
			pass
>>>>>>> origin/Development
		elif choice == '4':
			ds.setUserState(dbConfig, '7')
		elif choice == '5':
			ds.reinitAllUsers(dbConfig)
			ds.eContinue()
		elif choice == '0':
			loop = False
			return
### End ### Sub menus userIssue_menu ###

def userInfo_menu():
	menu = ['1. List all devices from db', '2. List of GMS users & emails', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
<<<<<<< HEAD
			ds.list_deviceInfo(dbConfig)
			ds.eContinue()
		elif choice == '2':
			ds.list_usersAndEmails(dbConfig)
			ds.eContinue()
=======
			pass
		elif choice == '2':
			pass
>>>>>>> origin/Development
		elif choice == '0':
			loop = False
			main_menu()

def checksQueries_menu():
<<<<<<< HEAD
	menu = ['1. General Health Check (beta)', '2. Nightly Maintenance Check', '\n     3. Show Sync Status', '4. GW pending events by User (consumerevents)', '5. Mobility pending events by User (syncevents)', '\n     6. Attachments...', '\n     0. Back']
=======
	menu = ['1. General Health Check (beta)', '2. Nightly Maintenance Check', '\n     3. Show Sync Status', '4. GW pending events by User (consumerevents)', '5. Mobility pending events by User (syncevents)', '\n     6. Attachments...', '7. Watch psql command (CAUTION)', '\n     0. Back']
>>>>>>> origin/Development

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
<<<<<<< HEAD
			ghc.generalHealthCheck(mobilityConfig, gwConfig, XMLconfig ,ldapConfig, dbConfig, trustedConfig, config_files, webConfig)
=======
			ghc.generalHealthCheck(mobilityConfig, gwConfig, XMLconfig ,ldapConfig, dbConfig, trustedConfig, config_files)
>>>>>>> origin/Development
			print; ds.eContinue()
		elif choice == '2':
			print ds.checkNightlyMaintenance(config_files, mobilityConfig)['output']
			print; ds.eContinue()
		elif choice == '3':
			ds.datasyncBanner(dsappversion)
			ds.showStatus(dbConfig)
			print; ds.eContinue()
		elif choice == '4':
<<<<<<< HEAD
			ds.show_GW_syncEvents(dbConfig)
			print; ds.eContinue()
		elif choice == '5':
			ds.show_Mob_syncEvents(dbConfig)
			ds.eContinue()
		elif choice == '6':
			viewAttachments_menu()
=======
			pass
		elif choice == '5':
			pass
		elif choice == '6':
			viewAttachments_menu()
		elif choice == '7':
			pass
>>>>>>> origin/Development
		elif choice == '0':
			loop = False
			main_menu()

### Start ### Sub menus checkQueries_menu ###
def viewAttachments_menu():
<<<<<<< HEAD
	menu = ['1. View attachments by user', '2. Check Mobility attachments count', '\n     0. Back']
=======
	menu = ['1. View attachments by user', '2. Check Mobility attachments', '3. Check Mobility attachments count (beta)', '\n     0. Back']
>>>>>>> origin/Development

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
<<<<<<< HEAD
			ds.view_attach_byUser(dbConfig)
			ds.eContinue()
		elif choice == '2':
			ds.check_mob_attachments(dbConfig)
			print; ds.eContinue()
=======
			pass
		elif choice == '2':
			pass
		elif choice == '3':
			pass
>>>>>>> origin/Development
		elif choice == '0':
			loop = False
			return
### End ### Sub menus checkQueries_menu ###