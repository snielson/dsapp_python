import sys
import os
import dsappDefinitions as ds
import logging, logging.config
import ConfigParser
Config = ConfigParser.ConfigParser()

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


def show_menu(list_call):
	ds.datasyncBanner(dsappversion)
	menu = globals()[list_call]()

	for i in range(len(menu['menu'])):
		print menu['menu'][i]

	return menu


def test_out():
	print "This was selected."

##################################################################################################
#	Menus
##################################################################################################

def main_menu():
	menu = ['1. Logs', '2. Register & Update', '3. Database', '4. Certificates', '5. User Issues', '6. User Info', '7. Checks & Queries', '0. Quit']
	# keys = {'menu': menu, '1': None,'2': None, '3': None, '4': None, '5': None, '6': None, '7': None, '0': None}
	keys = {'menu': menu, '1': test_out,'2': 'cake', '3': None, '4': None, '5': None, '6': None, '7': None, '0': 'break'}
	return keys