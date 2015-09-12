import sys
import os
import dsappDefinitions as ds
import logging, logging.config
import ConfigParser
Config = ConfigParser.ConfigParser()
import getch
getch = getch._Getch()

# Folder variables
dsappDirectory = "/opt/novell/datasync/tools/dsapp"
dsappConf = dsappDirectory + "/conf"
dsappLogs = dsappDirectory + "/logs"
dsapplib = dsappDirectory + "/lib"
dsappBackup = dsappDirectory + "/backup"
dsapptmp = dsappDirectory + "/tmp"
dsappupload = dsappDirectory + "/upload"
rootDownloads = "/root/Downloads"
dsappSettings = dsappConf + "/setting.cfg"

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (dsappConf))
logger = logging.getLogger('__main__')

# Read Config
Config.read(dsappSettings)
dsappversion = Config.get('Misc', 'dsapp.version')


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
	menu = ['1. Logs', '2. Register & Update', '3. Database', '4. Certificates', '5. User Issues', '6. User Info', '7. Checks & Queries', '0. Quit']
	sub_menus = {'1': log_menu,'2': registerUpdate_menu, '3': database_menu, '4': certificate_menu, '5': userIssue_menu, '6': userInfo_menu, '7': checksQueries_menu}
	
	available = build_avaialbe(menu)
	show_menu(menu)
	choice = get_choice(available, 'd')
	if choice == '0':
		return
	elif choice == 'd':
		pass # TODO : Log into database
	sub_menus[choice]()


## Sub menus  ##

def log_menu():
	menu = ['1. Upload logs', '2. Set logs to defaults', '3. Set logs to diagnostics/debug', '4. Log Capture', '5. Remove log archives', '0. Back']
	
	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			pass
		elif choice == '2':
			pass
		elif choice == '3':
			pass
		elif choice == '4':
			pass
		elif choice == '5':
			pass
		elif choice == '0':
			loop = False
			main_menu()

def registerUpdate_menu():
	menu = ['1. Register Mobility', '2. Update Mobility', '3. Apply FTF / Patch Files', '0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			pass
		elif choice == '2':
			pass
		elif choice == '3':
			pass
		elif choice == '0':
			loop = False
			main_menu()

def certificate_menu():
	menu = ['1. Generate self-signed certificate', '2. Create CSR & Private key', '3. Install certificate from 3rd party', '4. Verify certificate / key pair', '0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			pass
		elif choice == '2':
			pass
		elif choice == '3':
			pass
		elif choice == '4':
			pass
		elif choice == '0':
			loop = False
			main_menu()

def userIssue_menu():
	menu = ['1. Monitor user sync options...', '2. GroupWise checks options...', '3. Remove & reinitialize users options...', '4. User authentication issues', '5. Change user application name', '6. Change user FDN', '7. What deleted this (contact, email, folder, calendar)?', '8. List subjects of deleted items from device', '0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			pass
		elif choice == '2':
			pass
		elif choice == '3':
			pass
		elif choice == '4':
			pass
		elif choice == '5':
			pass
		elif choice == '6':
			pass
		elif choice == '7':
			pass
		elif choice == '8':
			pass
		elif choice == '0':
			loop = False
			main_menu()

def userInfo_menu():
	menu = ['1. List all devices from db', '2. List of GMS users & emails', '0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			pass
		elif choice == '2':
			pass
		elif choice == '0':
			loop = False
			main_menu()

def checksQueries_menu():
	menu = ['1. General Health Check (beta)', '2. Nightly Maintenance Check', '3. Show Sync Status', '4. GW pending events by User (consumerevents)', '5. Mobility pending events by User (syncevents)', '6. Attachments...', '7. Watch psql command (CAUTION)', '0. Back']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			pass
		elif choice == '2':
			pass
		elif choice == '3':
			pass
		elif choice == '4':
			pass
		elif choice == '5':
			pass
		elif choice == '6':
			pass
		elif choice == '7':
			pass
		elif choice == '0':
			loop = False
			main_menu()

def database_menu():
	menu = ['1. Vacuum Databases', '2. Re-Index Databases', '3. Back up Databases', '4. Restore Databases', '5. Recreate Global Address Book (GAL)', '6. Fix targets/membershipCache', '7. CUSO Clean-Up Start-Over', '0. Back -- Start Mobility']

	available = build_avaialbe(menu)
	loop = True
	while loop:
		show_menu(menu)
		choice = get_choice(available)
		if choice == '1':
			pass
		elif choice == '2':
			pass
		elif choice == '3':
			pass
		elif choice == '4':
			pass
		elif choice == '5':
			pass
		elif choice == '6':
			pass
		elif choice == '7':
			pass
		elif choice == '0':
			loop = False
			main_menu()