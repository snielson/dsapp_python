#!/usr/bin/env python
# Written by Shane Nielson <snielson@projectuminfinitas.com>
__author__ = "Shane Nielson"
__credits__ = "Tyler Harris"
__maintainer__ = "Shane Nielson"
__email__ = "snielson@projectuminfinitas.com"

import sys
import os
import traceback
import dsapp_Definitions as ds
import logging, logging.config
import signal
import ConfigParser
Config = ConfigParser.ConfigParser()
import getch
getch = getch._Getch()
import textwrap
import subprocess
import imp
pydoc = imp.load_source('pydoc', os.path.dirname(os.path.realpath(__file__)) + '/pydoc.py')
from locale import getpreferredencoding
import subprocess
from tabulate import tabulate

import dsapp_ghc as ghc
import dsapp_Soap as dsSOAP
import dsapp_performance as dsPerformance
import dsapp_acme as acme

# Globals
import dsapp_global as glb

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (glb.dsappConf))
logger = logging.getLogger('__main__')
excep_logger = logging.getLogger('exceptions_log')

def my_handler(type, value, tb):
	tmp = traceback.format_exception(type, value, tb)
	logger.error("EXCEPTION: See exception.log")
	excep_logger.error("Uncaught exception:\n%s" % ''.join(tmp).strip())
	print ''.join(tmp).strip()

def preexec_function():
	# Ignore the SIGINT signal by setting the handler to the standard
	# signal handler SIG_IGN.
	signal.signal(signal.SIGINT, signal.SIG_IGN)

# Install exception handler
sys.excepthook = my_handler

# Read Config
Config.read(glb.dsappSettings)
temp_updateURL = Config.get('Update URL', 'download.address')

# Set updateURL variable based on setting.cfg
from urlparse import urlparse
o = urlparse(temp_updateURL)
temp_urlOut = o.netloc + o.path
temp_scheme = o.scheme.strip().upper()
if 'FTP' in temp_scheme:
	scheme_URL = 'FTP'
else:
	scheme_URL = 'URL'

# Define update URL as default
updateURL = "URL"
try:
	updateURL = "%s (%s)" % (scheme_URL, temp_urlOut.split('/')[0].strip())
except:
	pass

def show_menu(menu_call):
	ds.datasyncBanner()
	logger.debug("Showing menu options: %s" % menu_call)

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
			logger.debug("Selected option: %s" % choice)
			return special
		elif choice in available or choice == 'q' or choice == 'Q':
			if choice == '0' or choice == 'q' or choice == 'Q':
				print
				logger.debug("Selected option: 0")
				return '0'
			else:
				print
				logger.debug("Selected option: %s" % choice)
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
	ds.print_there(23,6, glb.DISCLAIMER)
	
	choice = get_choice(available, 'd')
	if choice == '0':
		loop = False
		ds.clear()
		return
	elif choice == 'd':
		logger.debug("Entering datasync database")
		cmd = "PGPASSWORD='%(pass)s' psql -U %(user)s datasync" % glb.dbConfig
		ds.clear()
		p = subprocess.Popen(cmd, shell=True, preexec_fn = preexec_function)
		p.wait()
		main_menu()
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
			ds.getLogs()
			print; ds.eContinue()
		elif choice == '2':
			ds.cleanLog()
			print; ds.eContinue()
		elif choice == '0':
			loop = False
			main_menu()

def registerUpdate_menu():
	menu = ['1. Register Mobility', '2. Update Mobility', '3. FTF options..', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.datasyncBanner()
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
			ds.datasyncBanner()

			Config.read(glb.dsappSettings)
			serviceCheck = Config.get('FTF URL', 'check.service.address')
			serviceCheckPort = Config.getint('FTF URL', 'check.service.port')
			dlPath = Config.get('FTF URL', 'download.address')
			if ds.DoesServiceExist(serviceCheck, serviceCheckPort):
				# Get latest FTFlist.txt file
				FTFfile = glb.dsappConf + '/dsapp_FTFlist.txt'
				if os.path.isfile(FTFfile):
					os.rename(FTFfile, FTFfile + '.bak')

				if not ds.dlfile('%sdsapp_FTFlist.txt' % dlPath, glb.dsappConf, False, False):
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
	menu = ['1. Update via Local ISO', '2. Update via %s' % updateURL, '\n     0. Back']

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
	ds.datasyncBanner()
	print "The database menu will require Mobility to be stopped"
	if ds.askYesOrNo("Stop Mobility now"):
		ds.datasyncBanner()
		ds.rcDS('stop')
		menu = ['1. Vacuum Databases', '2. Re-Index Databases', '\n     3. Back up Databases', '4. Restore Databases', '\n     5. Recreate Global Address Book (GAL)', '6. Fix targets/membershipCache', '\n     7. CUSO Clean-Up Start-Over', '\n     0. Back -- Start Mobility']

		available = build_avaialbe(menu)
		loop = True
		while loop:
			show_menu(menu)
			choice = get_choice(available)
			if choice == '1':
				ds.datasyncBanner()
				print textwrap.fill("The amount of time this takes can vary depending on the last time it was completed. It is recommended that this be run every 6 months.", 80)
				print
				if ds.askYesOrNo("Do you want to continue"):
					ds.vacuumDB()
					print
					ds.eContinue()
			elif choice == '2':
				ds.datasyncBanner()
				print textwrap.fill("The amount of time this takes can vary depending on the last time it was completed. It is recommended that this be run after a database vacuum.", 80)
				print
				if ds.askYesOrNo("Do you want to continue"):
					ds.indexDB()
					print
					ds.eContinue()
			elif choice == '3':
				ds.backupDatabase()
				print; ds.eContinue()
			elif choice == '4':
				ds.restoreDatabase()
				print; ds.eContinue()
			elif choice == '5':
				ds.fix_gal()
				print; ds.eContinue()
			elif choice == '6':
				ds.addGroup()
				print; ds.eContinue()
			elif choice == '7':
				cuso_menu()
			elif choice == '0':
				loop = False
				ds.datasyncBanner()
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
			ds.datasyncBanner()
			if ds.askYesOrNo("Clean up and start over (Except Users)"):
				ds.cuso('user')
				print; ds.eContinue()
		elif choice == '2':
			ds.datasyncBanner()
			if ds.askYesOrNo("Clean up and start over (Everything)"):
				ds.cuso('everything')
				print; ds.eContinue()
		elif choice == '3':
			ds.datasyncBanner()
			print "Please run 'sh /opt/novell/datasync/uninstall.sh' first"
			if ds.askYesOrNo("Uninstall Mobility"):
				ds.cuso('uninstall')
		elif choice == '0':
			loop = False
			return
### End ### Sub menu for database_menu ###

def certificate_menu():
	menu = ['1. Generate CSR & Private key', '2. Generate self-signed certificate', '3. Apply certificates (Generate PEM)', '4. Verify certificate / key pair', '\n     5. LetsEncrypt..','\n     0. Back']
	
	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)

		# Check certs each loop (If they are changed)
		try:
			mob_result = ds.getExpiry(glb.mobileCertPath)[0].split('=')[1]
			ds.print_there(22,6, "Device (mobility.pem) expiry date: %s" % mob_result)
		except:
			pass
		try:
			ser_result = ds.getExpiry(glb.serverCertPath)[0].split('=')[1]
			ds.print_there(23,6, "Webadmin (server.pem) expiry date: %s" % ser_result)
		except:
			pass

		choice = get_choice(available)
		if choice == '1':
			ds.createCSRKey()
			print; ds.eContinue()
		elif choice == '2':
			ds.pre_signCert()
			print; ds.eContinue()
		elif choice == '3':
			ds.createPEM()
			print; ds.eContinue()
		elif choice == '4':
			ds.verifyCertifiateMatch()
			print; ds.eContinue()
		elif choice == '5':
		     letsEncrypt_menu()
		elif choice == '0':
			loop = False
			main_menu()

### Start ### Sub menu for letsEncrypt_menu ###
def letsEncrypt_menu():
	a = acme.acme()
	
	loop = True
	while loop:
		a.clearDNS()
		# Make dynamic menu
		if a.getAcmeInstalled():
			is_acmeInstalled = "Uninstall"
		else:
			is_acmeInstalled = "Install"
		if a.getCronInstalled():
			is_cronInstalled = "Uninstall"
		else:
			is_cronInstalled = "Setup"
	# Dynamic menu based on acme or cron installed
		menu = ['1. %s acme.sh' % is_acmeInstalled, '2. Issue certificate', '\n     3. %s auto renew' % is_cronInstalled, '\n     0. Back']

		available = build_avaialbe(menu)
	
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			if not a.getAcmeInstalled():
				ds.datasyncBanner()
				a.setupAcme()
				print; ds.eContinue()
			else:
				ds.datasyncBanner()
				a.removeAcme()
				print; ds.eContinue()
		elif choice == '2':
			ds.datasyncBanner()
			a.autoIssue()
			print; ds.eContinue()
		elif choice == '3':
			if not a.getCronInstalled():
				ds.datasyncBanner()
				a.setAutoRenew()
				print; ds.eContinue()
			else:
				ds.datasyncBanner()
				a.uninstallAutoRenew()
				print; ds.eContinue()
		elif choice == '0':
			loop = False
			return

### End ### Sub menu for letsEncrypt_menu ###

def userIssue_menu():
	menu = ['1. Monitor user sync options..', '2. GroupWise checks options..', '3. Remove & reinitialize users options..', '\n     4. User authentication issues', '5. Change user application name', '6. Change user FDN', '7. What deleted this (contact, email, folder, calendar)?', '8. Remove devices', '\n     0. Back']

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
			ds.check_userAuth()
		elif choice == '5':
			ds.changeAppName()
		elif choice == '6':
			ds.updateFDN()
		elif choice == '7':
			ds.whereDidIComeFromAndWhereAmIGoingOrWhatHappenedToMe()
		elif choice == '8':
			remove_device_menu()
		elif choice == '0':
			loop = False
			main_menu()

### Start ### Sub menus remove_device_menu ###
def remove_device_menu():
	menu = ['1. Remove all devices', '2. Remove user devices', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.datasyncBanner()
			if ds.askYesOrNo("Remove all users devices"):
				ds.removeDevice()
		elif choice == '2':
			userConfig = ds.verifyUser()[0]
			if ds.confirm_user(userConfig, 'mobility'):
				if ds.askYesOrNo("Remove all devices for %s" % userConfig['name']):
					ds.removeDevice(userConfig)
			else:
				ds.eContinue()
		elif choice == '0':
			loop = False
			return

### Start ### Sub menus userIssue_menu ###
def monitorUser_menu():
	menu = ['1. Monitor user(s) sync state (Mobility)', '2. Monitor user sync GW/MC count (Sync-Validate)', '3. Monitor active users sync state', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.monitorUser()
		elif choice == '2':
			ds.monitor_Sync_validate()
		elif choice == '3':
			ds.monitor_syncing_users()
		elif choice == '0':
			loop = False
			return

def groupwiseChecks_menu():
	menu = ['1. Check user over SOAP', '2. Check GroupWise folder structure', '\n     3. Count user shared folders', '4. Count all users shared folders', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			userConfig = ds.verifyUser()[0]
			if userConfig['name'] != None:
				if userConfig['type'] != 'group':
					dsSOAP.soap_printUser(userConfig)
				else:
					print ("Input '%(name)s' is not a user. Type='%(type)s'" % userConfig)
				print; ds.eContinue()

		elif choice == '2':
			dsSOAP.soap_checkFolderList(ds.verifyUser()[0])

		elif choice == '3':
			userConfig = ds.verifyUser()[0]
			if userConfig['name'] != None:
				if userConfig['type'] != 'group':
					shared_list = dsSOAP.soap_check_sharedFolders(userConfig)
					if shared_list is not None:
						pydoc.pager(shared_list)
						if ds.askYesOrNo("Save to file"):
							with open(glb.dsappdata + '/shared_folder_list.txt', 'w') as file:
								file.write(shared_list)
								file.write('\n')
							logger.info("Saving shared list to %s" % (glb.dsappdata + '/shared_folder_list.txt'))
							print ("Saved to %s" % (glb.dsappdata + '/shared_folder_list.txt'))
					print; ds.eContinue()

		elif choice == '4':
			ds.datasyncBanner()
			print ("This can take some time to check every user in mobility")
			if ds.askYesOrNo("Warning! CPU may become busy. Continue"):
				userList = ds.getMobilityUserList()
				shared_list = dsSOAP.soap_check_allSharedFolders(userList)
				if shared_list is not None:
					pydoc.pager(shared_list)
					if ds.askYesOrNo("Save to file"):
						with open(glb.dsappdata + '/shared_folder_list-allUsers.txt', 'w') as file:
							file.write(shared_list)
							file.write('\n')
						logger.info("Saving shared list to %s" % (glb.dsappdata + '/shared_folder_list-allUsers.txt'))
						print ("Saved to %s" % (glb.dsappdata + '/shared_folder_list-allUsers.txt'))
					print; ds.eContinue()
					
		elif choice == '0':
			loop = False
			return

def removeUser_menu():
	menu = ['1. Force remove user(s)/group(s) db references', '2. Remove user/group (restarts configengine)', '3. Remove disabled users & fix referenceCount', '\n     4. Reinitialize user(s)', '5. Reinitialize all failed users', '6. Reinitialize all users', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.remove_user(1)
		elif choice == '2':
			ds.remove_user()
		elif choice == '3':
			ds.datasyncBanner()
			ds.removed_disabled()
			print
			ds.fix_referenceCount()
			print; ds.eContinue()
		elif choice == '4':
			ds.setUserState('7')
		elif choice == '5':
			ds.reinitAllFailedUsers()
			print;ds.eContinue()
		elif choice == '6':
			ds.reinitAllUsers()
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
			ds.list_deviceInfo()
		elif choice == '2':
			ds.list_usersAndEmails()
		elif choice == '3':
			ds.getUserPAB()
		elif choice == '0':
			loop = False
			main_menu()

def checksQueries_menu():
	menu = ['1. General Health Check', '2. Nightly Maintenance Check', '\n     3. Show Sync Status', '4. GW pending events by User (consumerevents)', '5. Mobility pending events by User (syncevents)', '\n     6. Attachments..', '7. Performance..', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ghc.generalHealthCheck()
			print; ds.eContinue()
		elif choice == '2':
			print ds.checkNightlyMaintenance()['output']
			print; ds.eContinue()
		elif choice == '3':
			ds.datasyncBanner()
			ds.showStatus()
			print; ds.eContinue()
		elif choice == '4':
			ds.show_GW_syncEvents()
		elif choice == '5':
			ds.show_Mob_syncEvents()
		elif choice == '6':
			viewAttachments_menu()
		elif choice == '7':
			performance_menu()
		elif choice == '0':
			loop = False
			main_menu()

### Start ### Sub menu performance_menu ###
def performance_menu():
	menu = ['1. Top device requests','2. Check manual syncing devices', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		ds.print_there(23,6, "DEBUG logging required. Logs parsed for data")
		choice = get_choice(available)
		if choice == '1':
			ds.datasyncBanner()
			if ds.askYesOrNo("Parse debug log for top device requests"):
				log = ds.getFilePath("mobility-agent log file",'/var/log/datasync/connectors/mobility-agent.log')
				if log is None:
					return
				dsPerformance.getDeviceCommands(log)
				ds.eContinue()

		elif choice == '2':
			ds.datasyncBanner()
			if ds.askYesOrNo("Parse debug log for devices set to manual sync"):
				log = ds.getFilePath("mobility-agent log file",'/var/log/datasync/connectors/mobility-agent.log')
				if log is None:
					return
				dsPerformance.getPinglessDevices(log)
				ds.eContinue()

		elif choice == '0':
			loop = False
			return
### End ### Sub menus performance_menu ###

### Start ### Sub menus checkQueries_menu ###
def viewAttachments_menu():
	menu = ['1. View user attachments','2. View total attachment size by users', '3. Check Mobility attachments count', '\n     0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			ds.view_users_attach()
		elif choice == '2':
			ds.view_attach_byUser()
		elif choice == '3':
			ds.datasyncBanner()
			print ("Compare the mobility database ID count, with the mobility filestore ID count")
			if ds.askYesOrNo("This may take some time to complete, continue"):
				ds.check_mob_attachments()
				print; ds.eContinue()
		elif choice == '0':
			loop = False
			return
### End ### Sub menus checkQueries_menu ###


# DEBUG MENU
def debug_menu():
	menu = ['DEBUG MENU\n','1. SOAP - View user folder list', '2. SOAP - View user address book list', '3. SOAP - getUserListRequest', '4. View verifyUser data', '5. View variables', '\n     0. Quit']
	logger.info("Running DEBUG menu!")

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			logger.info("DEBUG MENU: Checking SOAP folder check")
			userConfig = ds.verifyUser()[0]
			if userConfig['name'] is not None:
				pydoc.pager(str(dsSOAP.soap_checkFolderListTEST(userConfig)))

		elif choice == '2':
			logger.info("DEBUG MENU: Checking SOAP address book check")
			userConfig = ds.verifyUser()[0]
			if userConfig['name'] is not None:
				pydoc.pager(str(dsSOAP.soap_checkAddressBookListTEST(userConfig)))

		elif choice =='3':
			gw_location = "%(sSecure)s://%(gListenAddress)s:%(sPort)s/soap" % glb.gwConfig
			info = "Trusted Name: %s\nTrusted Key: %s\nAddress: %s\n\n" % (glb.trustedConfig['name'], glb.trustedConfig['key'],gw_location)
			info += str(dsSOAP.soap_getUserList())
			pydoc.pager(info)

		elif choice == '4':
			logger.info("DEBUG MENU: Running verifyUser()")
			for user in ds.verifyUser():
				print user
				print
			ds.eContinue()
		elif choice == '5':
			logger.info("DEBUG MENU: Listing variables")
			saved_variables = ("Database Config:\n%s\n" % glb.dbConfig)
			saved_variables += ("\nLDAP Config:\n%s\n" % glb.ldapConfig)
			saved_variables += ("\nMobility Config:\n%s\n" % glb.mobilityConfig)
			saved_variables += ("\nGroupWise Config:\n%s\n" % glb.gwConfig)
			saved_variables += ("\nTrusted App Config:\n%s\n" % glb.trustedConfig)
			saved_variables += ("\nConfig Files:\n%s\n" % glb.config_files)
			saved_variables += ("\nWeb Config:\n%s\n" % glb.webConfig)
			saved_variables += ("\nAuth Config:\n%s\n" % glb.authConfig)
			pydoc.pager(saved_variables)

		elif choice == '0':
			loop = False
			ds.clear()
			return
