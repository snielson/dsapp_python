from __future__ import print_function
import os
import sys
import signal
import getpass
import shutil
import fileinput
import glob
import subprocess
import re
import xml.etree.ElementTree as ET
import logging
import logging.config

# Log Settings
# TODO: Change logger level via switch
logging.config.fileConfig('./conf/logging.conf')
logger = logging.getLogger(__name__)

def clear():
	tmp = os.system('clear')

def datasyncBanner(dsappversion):
	banner="""
         _
      __| |___  __ _ _ __  _ __
     / _' / __|/ _' | '_ \\| '_ \\
    | (_| \__ | (_| | |_) | |_) |
     \__,_|___/\__,_| .__/| .__/
                    |_|   |_|
	"""
	clear()
	print (banner + "\t\t      v" + dsappversion + "\n")

def check_pid(pid):        
  try:
    os.kill(pid, 0)
  except OSError:
    return False
  else:
    return True

def removeLine(filePath, line):
	for fLine in fileinput.input(filePath, inplace=True):
		if line in fLine:
			continue
		print(fLine, end='')

def removeAllFiles(path):
	filelist = glob.glob(path +"/*")
	for f in filelist:
		os.remove(f)

def eContinue():
   raw_input("Press Enter to continue: ")

def eContinueTime():
	# TODO:
	pass

def checkInstall(forceMode, installedConnector):
	if not forceMode:
		if not os.path.exists(installedConnector):
			sys.exit("Mobility is not installed")
			logger.info('Mobility is not installed')
		return True

def getVersion(isInstalled,version):
	if isInstalled:
		try:
			with open(version) as f:
				return f.read()
		except IOError:
			print ("Unable to find: ",version)
			logger.error('Unable to find: ' + version)
			sys.exit(1)

def findReplace(find, replace, filePath):
	for line in fileinput.input(filePath, inplace=True):
		print(line.replace(find,replace), end='')

def pushConf(attribute, value, filePath):
	find = str(attribute + "=.*")
	replace = str(attribute + "=" + value)

	logger.debug('Updating: ' + attribute + ' to: ' + value)
	for line in fileinput.input(filePath, inplace=True):
		print(re.sub(find, replace, line), end='')

# Python equiv linux grep
def pGrep(search, filePath):
	with open(filePath, 'r') as f:
		for line in f:
				if re.search(search, line) and line is not None:
					return line.rstrip()
		return ''

def getXMLTree(filePath):
	try:
		return ET.ElementTree(file=filePath)
		logger.debug(filePath + " loaded as XML tree")
	except IOError:
		print ('Unable to find file: ',filePath)
		logger.error('Unable to find file: ' + filePath)
		sys.exit(1)

def xmlpath (elem, tree):
	# Example of elem: './/configengine/ldap/enabled/'
	return (tree.find(elem).text)