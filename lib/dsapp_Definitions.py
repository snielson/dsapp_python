#!/usr/bin/env python
# Written by Shane Nielson <snielson@projectuminfinitas.com>
from __future__ import print_function

__author__ = "Shane Nielson"
__credits__ = "Tyler Harris"
__maintainer__ = "Shane Nielson"
__email__ = "snielson@projectuminfinitas.com"

import os,base64,sys,signal,select,getpass,shutil,fileinput,glob,time,datetime,pprint,textwrap
import subprocess,socket,re,rpm,contextlib
import tarfile, zipfile, bz2
from pipes import quote
import gzip
import imp
pydoc = imp.load_source('pydoc', os.path.dirname(os.path.realpath(__file__)) + '/pydoc.py')
import traceback
import urllib2
import readline
import operator
import StringIO
import tempfile
from multiprocessing import Process, Queue
from tabulate import tabulate
from urllib2 import urlopen, URLError, HTTPError
from xml.parsers.expat import ExpatError
import logging, logging.config
import ConfigParser
Config = ConfigParser.ConfigParser()

# Import requests as an alternative to urllib
import requests
# Hide requests warning (outdated python with GMS)
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

# import netifaces after appending to sys.path
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/netifaces-0.10.4-py2.6-linux-x86_64.egg')
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/setuptools-18.2-py2.6.egg')
from netifaces import interfaces, ifaddresses, AF_INET

from lxml import etree
# Pass import (GMS not installed)
try:
	import psycopg2
	import psycopg2.extras
	from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
except:
	pass

import spin
import filestoreIdToPath
import getch
getch = getch._Getch()
import dsapp_ghc as ghc
import dsapp_global as glb

if sys.stdout.isatty():
	WINDOW_SIZE = rows, columns = os.popen('stty size', 'r').read().split()
else:
	# Default terminal size
	WINDOW_SIZE = [24,80]

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (glb.dsappConf))
logger = logging.getLogger(__name__)
excep_logger = logging.getLogger('exceptions_log')

def my_handler(type, value, tb):
	tmp = traceback.format_exception(type, value, tb)
	logger.error("EXCEPTION: See exception.log")
	excep_logger.error("Uncaught exception:\n%s" % ''.join(tmp).strip())
	print (''.join(tmp).strip())

# Install exception handler
sys.excepthook = my_handler

# Text color formats
colorGREEN = "\033[01;32m{0}\033[00m"
colorRED = "\033[01;31m{0}\033[00m"
colorYELLOW = "\033[01;33m{0}\033[00m"
colorBLUE = "\033[01;34m{0}\033[00m"

def dsappExitError(message=None, exit=True, printMessage=False):
	ERROR_MSG1 = "\n\ndsapp has encountered an error. See log for more details\n%s/dsapp.log" % glb.dsappLogs
	ERROR_MSG2 = "\n\ndsapp has encountered an error."

	if message is not None: 
		if printMessage:
			print (ERROR_MSG2)
			print("Error: %s" % message)
		else:
			print (ERROR_MSG1)
		logger.error(message)
	else:
		print (ERROR_MSG1)
	if exit:
		sys.exit(1)

# Define Variables for Eenou+ (2.x)
def declareVariables2():
	logger.debug('Setting version variables for 2.X')
	glb.mAlog = glb.log + "/connectors/mobility-agent.log"
	glb.gAlog = glb.log + "/connectors/groupwise-agent.log"
	glb.mlog = glb.log + "/connectors/mobility.log"
	glb.glog = glb.log + "/connectors/groupwise.log"

# Define Variables for Pre-Eenou (1.x)
def declareVariables1():
	logger.debug('Setting version variables for 1.X')
	glb.mAlog = glb.log + "/connectors/default.pipeline1.mobility-AppInterface.log"
	glb.gAlog = glb.log + "/connectors/default.pipeline1.groupwise-AppInterface.log"
	glb.mlog = glb.log + "/connectors/default.pipeline1.mobility.log"
	glb.glog = glb.log + "/connectors/default.pipeline1.groupwise.log"

def set_spinner():
	spinner = spin.progress_bar_loading()
	spinner.setDaemon(True)
	return spinner

def print_disclaimer():
	datasyncBanner()
	prompt = 'Use at your own discretion. dsapp is not supported by Novell.\nSee [dsapp --bug] to report issues.'
	print (prompt)
	r,w,x = select.select([sys.stdin], [], [], 10)
	sys.stdout.flush()

def clear():
	tmp = subprocess.call('clear',shell=True)

def datasyncBanner():
	banner="""
         _
      __| |___  __ _ _ __  _ __
     / _' / __|/ _' | '_ \\| '_ \\
    | (_| \__ | (_| | |_) | |_) |
     \__,_|___/\__,_| .__/| .__/ 
                    |_|   |_|
	"""
	clear()
	if glb.forceMode:
		print (banner + "\t\t      v" + glb.dsappversion + " FORCED\n")
	else:
		print (banner + "\t\t      v" + glb.dsappversion + "\n")

def readlines_reverse(filename):
# Credit to Berislav Lopac on Stackoverflow
	with open(filename) as qfile:
		qfile.seek(0, os.SEEK_END)
		position = qfile.tell()
		line = ''
		while position >= 0:
			qfile.seek(position)
			next_char = qfile.read(1)
			if next_char == "\n":
				yield line[::-1]
				line = ''
			else:
				line += next_char
			position -= 1
		yield line[::-1]

def announceNewFeature():
	Config.read(glb.dsappSettings)
	newFeature = Config.getboolean('Settings', 'new.feature')

	if newFeature:
		datasyncBanner()
		logger.debug('Prompt feature')
		print ("New feature for GMS shared folders.\nCheck users shared folders, and total all users shares.\n\nOptions can be found at (5. User Issues, 2. GroupWise checks options)\nCounting all users shares can run about 8-10 users per minute.\n")
		eContinue()
		Config.read(glb.dsappSettings)
		Config.set('Settings', 'new.feature', False)
		with open(glb.dsappSettings, 'wb') as cfgfile:
			logger.debug("Writing: [Settings] new.feature = %s" % 'False')
			Config.write(cfgfile)
	else:
		logger.debug("New feature is set to False")

def check_pid(pid):        
  try:
    os.kill(pid, 0)
  except OSError:
    return False
  else:
    return True

def get_pid(name):
	return os.popen("pgrep -f '%s' "% (name)).read().split()

def kill_pid(pid, sig=1):
	try:
		os.kill(pid, sig)
		logger.info('Killing process: %s' %(pid))
	except OSError:
		logger.warning('No such process: %s' %(pid))

def getOS_Version():
	with open(glb.OS_VERSION_FILE, 'r') as f:
		return f.read().strip().split('Server')[1].strip().split(' ')[0]

def removeLine(filePath, search):
	found = False
	try:
		logger.debug("Searching for '%s' in %s" % (search, filePath))
		with open(filePath, 'r') as openFile:
			lines = openFile.readlines()
		with open(filePath, 'w') as openFile:
			lineNumber = 0
			for line in lines:
				lineNumber += 1
				if search not in line:
					openFile.write(line)
				else:
					logger.debug("Found line [%s] '%s'" % (lineNumber, line.strip()))
					found = True

			if not found:
				logger.debug("No results for '%s'" % search)
			else:
				logger.debug("Done removing all '%s' lines" % search)
	except OSError:
		logger.warning('No such file or directory: %s' + filePath)

def removeAllFiles(path):
	filelist = glob.glob(path +"/*")
	for f in filelist:
		try:
			os.remove(f)
		except OSError:
			if not os.path.isdir(f):
				logger.warning('No such file: %s' % (f))
		logger.debug('Removed: %s' % f)

def removeAllFolders(path):
	folderlist = glob.glob(path + "/*")
	for f in folderlist:
		try:
			shutil.rmtree(f)
		except OSError:
			if not os.path.isfile(f):
				logger.warning('No such directory: %s' % f)
		logger.debug('Removed: %s' % f)

def ip4_addresses():
	# Function credit to 'Harley Holcombe' via Stackoverflow.com
	ip_list = []
	for interface in interfaces():
		try:
			for link in ifaddresses(interface)[AF_INET]:
				ip_list.append(link['addr'])
		except:
			logger.debug("AF_INET: %s" % AF_INET)
			logger.debug("ifaddresses: %s" % ifaddresses(interface))
			
	return ip_list

def eContinue():
	if sys.stdout.isatty():
		print("Press Enter to continue ", end='')
		while True:
			enter = getch()
			if ord(enter) == 13:
				break
		print()

def break_loop():
	return True

def eContinueTime(timeout=5):
	if sys.stdout.isatty():
		signal.signal(signal.SIGALRM, break_loop)
		print("Press Enter to continue ", end='')
		signal.alarm(timeout)
		loop = True
		try:
			while loop:
				enter = getch()
				if ord(enter) == 13:
					loop = False
		except:
			loop = False
		signal.alarm(0)
		print()

def checkInstall():
	if not glb.forceMode:
		if not os.path.exists(glb.installedConnector):
			print ("Mobility is not installed")
			logger.info('Mobility is not installed')
			return False
	return True

def getVersion(isInstalled):
	if isInstalled:
		try:
			with open(glb.gmsVersion) as f:
				return f.read()
		except IOError:
			print ("Unable to find: ", glb.gmsVersion)
			logger.error('Unable to find: ' + glb.gmsVersion)
			sys.exit(1)

def getFilePath(prompt):
	while True:
		filePath = autoCompleteInput(prompt)
		if not os.path.isfile (filePath):
			if not askYesOrNo("Invalid path. Try again"):
				filePath = None
				break
		else:
			break
	return filePath

def findReplace(find, replace, filePath):
	for line in fileinput.input(filePath, inplace=True):
		print(line.replace(find,replace), end='')

def complete(text, state):
	return (glob.glob(text+'*')+[None])[state]

def autoCompleteInput(text):
	readline.set_completer_delims(' \t\n;')
	readline.parse_and_bind("tab: complete")
	readline.set_completer(complete)
	user_input = raw_input('%s' % text)
	return user_input

def pgrep(search, filePath, flag=0):
	# Python equiv linux grep
	if flag == '-i':
		flag = re.IGNORECASE
	results = []
	with open(filePath, 'r') as f:
		for line in f:
				if re.search(search, line, flags=flag) and line is not None:
					results.append(line.strip())
		return results

def util_subprocess(cmd, error=False):
	if not error:
		p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
		p.wait()
		out = p.communicate()
	elif error:
		p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		p.wait()
		out = p.communicate()
	return out

def print_there(x, y, text):
     sys.stdout.write("\x1b7\x1b[%d;%df%s\x1b8" % (x, y, text))
     sys.stdout.flush()

def getXMLTree(filePath):
	parser = etree.XMLParser(remove_blank_text=True)
	try:
		return etree.parse(filePath, parser)
		logger.debug(filePath + " loaded as XML tree")
	except IOError:
		dsappExitError('Unable to find file: %s' % filePath ,exit=True, printMessage=True)
	except ExpatError:
		dsappExitError('Unable to parse XML: %s' % filePath ,exit=True, printMessage=True)

def xmlpath (elem, tree):
	# Example of elem: './/configengine/ldap/enabled/'
	try:
		return (tree.find(elem).text)
	except AttributeError:
		logger.warning('Unable to find %s' % (elem))
		return None

def xmlpath_findall(elem, tree):
	xml_list = []
	try:
		for node in tree.findall(elem):
			xml_list.append(node.text)
		return (xml_list)
	except AttributeError:
		logger.warning('Unable to find %s' % (elem))
		return None

def setXML (elem, tree, value, filePath, hideValue=False):
	"""
	Example to use:
	setXML('.//configengine/ldap/groupContainer', glb.XMLconfig['ceconf'],"o=testgroup", glb.config_files['ceconf'])
	"""
	if hideValue:
		logValue = "*******"
	else:
		logValue = value

	root = tree.getroot()
	# path = root.xpath(elem)
	path = root.find(elem)
	if value is not None:
		path.clear()
		path.text = value
		try:
			# print (etree.tostring(root, pretty_print=True))
			etree.ElementTree(root).write(filePath, pretty_print=True)
			logger.debug("Set '%s' at %s in %s" % (logValue, elem, filePath))
		except:
			logger.warning('Unable to set %s at %s in %s' % (logValue, elem, filePath))
	else:
		logger.error("Value is None")

def insertXML (elem, tree, value, filePath, hideValue=False):
	"""
	Example to use:
	insertXML('.//configengine/ldap/groupContainer', glb.XMLconfig['ceconf'],"<groupContainer>o=testgroup</groupContainer>", glb.config_files['ceconf'])
	"""
	if hideValue:
		logValue = "*******"
	else:
		logValue = value

	root = tree.getroot()
	path = root.find(elem)
	parent = path.getparent()
	if value is not None:
		parent.insert(parent.index(path)+1, etree.fromstring(value))
		try:
			# print (etree.tostring(root, pretty_print=True))
			etree.ElementTree(root).write(filePath, pretty_print=True)
			logger.debug("Inserting '%s' at %s in %s" % (logValue, elem, filePath))
		except:
			logger.warning('Unable to insert %s at %s in %s' % (logValue, elem, filePath))
	else:
		logger.error("Value is None")

def deleteXML_elem(elem, tree):
	"""
	Example to use:
	setXML('.//configengine/ldap/groupContainer', glb.XMLconfig['ceconf'],"o=testgroup", glb.config_files['ceconf'])
	"""
	root = tree.getroot()
	# path = root.xpath(elem)
	path = root.find(elem)
	root.remote(path)

	print (root)
		# try:
		# 	# print (etree.tostring(root, pretty_print=True))
		# 	etree.ElementTree(root).write(filePath, pretty_print=True)
		# 	logger.debug("Set '%s' at %s in %s" % (logValue, elem, filePath))
		# except:
		# 	logger.warning('Unable to set %s at %s in %s' % (logValue, elem, filePath))

def createXML_tag(elem, tree, tag, filePath, value=None, hideValue=False):
	"""
	Example to use:
	createXML_tag('.//configengine/ldap', glb.XMLconfig['ceconf'],"users", glb.config_files['ceconf'], value="o=novell")
	"""
	if hideValue:
		logValue = "*******"
	else:
		logValue = value

	root = tree.getroot()
	path = root.find(elem)
	if tag is not None:
		if value is not None:
			logger.debug("Adding '%s' to tag" % value)
			etree.SubElement(path, tag).text = value
		else:
			etree.SubElement(path, tag)

		try:
			# print (etree.tostring(root, pretty_print=True))
			etree.ElementTree(root).write(filePath, pretty_print=True)
			logger.debug("Creating tag '%s' at %s in %s" % (tag, elem, filePath))
		except:
			logger.warning("Unable to create tag '%s' at %s in %s" % (tag, elem, filePath))
	else:
		logger.error("Tag is None")


def askYesOrNo(question, default=None):

    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    elif default == 'skip':
    	return True
    else:
        raise ValueError("Invalid default answer: '%s'" % default)

    try:
        while True:
            choice = raw_input(question + prompt).lower()
            if default is not None and choice == '':
            	logger.debug('%s: %s' % (question, valid[default]))
            	return valid[default]
            elif choice in valid:
            	logger.debug('%s: %s' % (question, valid[choice]))
            	return valid[choice]
            else:
                sys.stdout.write("Please respond with 'yes' or 'no' "
                                 "(or 'y' or 'n').\n")
    except KeyboardInterrupt:
    	logger.warning("KeyboardInterrupt detected")

def unzip_file(fileName):
	with contextlib.closing(zipfile.ZipFile(fileName, 'r')) as z:
	    z.extractall()

def untar_file(fileName, extractPath="."):
	with contextlib.closing(tarfile.open(fileName, 'r:*')) as tar:
		tar.extractall(path=extractPath)

def uncompressIt(fileName):
	extension = os.path.splitext(fileName)[1]
	options = {'.tar': untar_file,'.zip': unzip_file, '.tgz': untar_file}
	logger.debug("Uncompressing %s with %s extension" % (fileName, extension))
	options[extension](fileName)

def zip_content(fileName):
	with contextlib.closing(zipfile.ZipFile(fileName, 'r')) as z:
		return z.namelist()

def tar_content(fileName):
	with contextlib.closing(tarfile.open(fileName, 'r:*')) as tar:
		return tar.getnames()

def file_content(fileName):
	extension = os.path.splitext(fileName)[1]
	options = {'.tar': tar_content,'.zip': zip_content, '.tgz': tar_content}
	logger.debug("Getting %s content with %s extension" % (fileName, extension))
	return options[extension](fileName)

def DoesServiceExist(host, port):
    captive_dns_addr = ""
    host_addr = ""

    try:
        captive_dns_addr = socket.gethostbyname("thisURLdoesntexistfakefakefake.com")
    except:
        pass

    try:
        host_addr = socket.gethostbyname(host)

        if (captive_dns_addr == host_addr):
        	logger.warning('Failed to test to %s:%s' %(host,port))
        	return False

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        s.close()
    except:
    	logger.warning('Failed to test to %s:%s' %(host,port))
    	return False

    logger.info('Successfully tested to %s:%s' %(host,port))
    return True

def dlfile(url,path=None, print_url=True, print_warn=True):
	# Open the url
	spinner = set_spinner()
	save_path = None
	try:
		f = urlopen(url)
		if print_url:
			print ("Downloading %s " % (url), end='')
			spinner.start(); time.sleep(.000001)
		logger.info('Downloading %s' % (url))
		# Open our local file for writing
		if path == None:
			save_path = os.path.basename(url)
		else:
			save_path = path + '/' + os.path.basename(url)
		with open(save_path, "wb") as local_file:
				local_file.write(f.read())

	#handle errors
	except HTTPError, e:
		logger.warning("HTTP Error: %s %s" %(e.reason, url))
		return False
	except URLError, e:
		if print_warn:
			print ("No such file or directory %s" % url)
		logger.warning("URL Error: %s %s" %(e.reason, url))
		return False
	else:
		return True
	finally:
		if print_url:
			spinner.stop(); print()

def download_file(url,path=None, print_url=True, print_warn=True):
	# Credit to Roman Podlinov @ http://stackoverflow.com/questions/16694907/how-to-download-large-file-in-python-with-requests-py
	spinner = set_spinner()
	save_path = None

	header = requests.head(url)
	if header.status_code == 404:
		print ("%s: %s" % (header.headers['Status'], url))
		logger.warning("%s: %s" % (header.headers['Status'], url))
		return False

	if print_url:
		print ("Downloading %s " % (url), end='')
		spinner.start(); time.sleep(.000001)

	if path == None:
		save_path = os.path.basename(url)
	else:
		save_path = path + '/' + os.path.basename(url)

	r = requests.get(url, stream=True)
	with open(save_path, 'wb') as f:
		for chunk in r.iter_content(chunk_size=1024): 
			if chunk: # filter out keep-alive new chunks
				f.write(chunk)
				# f.flush() commented by recommendation from J.F.Sebastian
	if print_url:
		spinner.stop(); print()

	return True

def updateDsapp(publicVersion, rpmFileLocation=None):
	if rpmFileLocation is None:
		print ('Updating dsapp to v%s' % (publicVersion))
		logger.info('Updating dsapp to v%s' % (publicVersion))
		Config.read(glb.dsappSettings)
		dlPath = Config.get('dsapp URL', 'download.address')
		fileName = Config.get('dsapp URL', 'download.filename')

		# Download new version & extract
		if not download_file('%s%s' % (dlPath, fileName)): return
		print ()
	else:
		fileName = rpmFileLocation

	files = file_content(fileName)
	logger.debug("File content: %s" % files)
	rpmFile = None
	for file in files:
		if 'rpm' in file:
			rpmFile = file
	if rpmFile is None:
		print ("Unable to find a valid RPM in: %s" % fileName)
		logger.error("Unable to find a valid RPM in: %s" % fileName)
		return

	uncompressIt(fileName)
	check_rpm = checkRPM(rpmFile)
	if check_rpm:
		setupRPM(rpmFile)
		Config.read(glb.dsappSettings)
		Config.set('Misc', 'dsapp.version', publicVersion)
		with open(glb.dsappSettings, 'wb') as cfgfile:
			logger.debug("Writing: [Misc] dsapp.version = %s" % publicVersion)
			Config.write(cfgfile)
		print ("Exiting dsapp..")
	elif check_rpm == None:
		setupRPM(rpmFile, 'i')
	else:
		print ('%s is older than installed version' % (rpmFile))
		logger.warning('%s is older than installed version' % (rpmFile))

	# Clean up files
	try:
		os.remove(rpmFile)
	except OSError:
		logger.warning('No such file: %s' % (rpmFile))
	try:
		os.remove(fileName)
	except OSError:
		logger.warning('No such file: %s' % (fileName))

	sys.exit(0)


def autoUpdateDsapp(skip=False):
	# Assign variables based on settings.cfg
	Config.read(glb.dsappSettings)
	autoUpdate = Config.getboolean('Settings', 'auto.update')
	serviceCheck = Config.get('dsapp URL', 'check.service.address')
	serviceCheckPort = Config.getint('dsapp URL', 'check.service.port')
	dlPath = Config.get('dsapp URL', 'download.address')
	dsapp_version_file = Config.get('dsapp URL', 'version.download.filename')
	warning = False

	# Variable declared above autoUpdate=true
	if skip:
		autoUpdate = True

	if autoUpdate:
		# Check FTP connectivity
		if DoesServiceExist(serviceCheck, serviceCheckPort):
			# Fetch online dsapp and store to memory, check version
			spinner = set_spinner()
			logger.info('Checking for a newer version of dsapp')
			print ('Checking for a newer version of dsapp... ', end='')
			spinner.start(); time.sleep(.000001)
			try:
				publicVersion = requests.get('%s%s' % (dlPath, dsapp_version_file)).text.split("'")[1]
			except:
				warning = True

			spinner.stop(); print ()
			clear()
			if warning:
				print ("Unable to check latest version")
				logger.warning("Unable to check latest version") 
				return
			
			# Download if newer version is available
			if glb.dsappversion < publicVersion and publicVersion is not None:
				print ('v%s (v%s available)' % (glb.dsappversion, publicVersion))
				logger.info('Updating dsapp v%s to v%s' % (glb.dsappversion, publicVersion))
				updateDsapp(publicVersion)
			elif glb.dsappversion >= publicVersion and publicVersion is not None:
				print ('dsapp is current at v%s' % glb.dsappversion)
				logger.info('dsapp is current at v%s' % glb.dsappversion)
		else:
			print ("Unable to reach %s:%s\n" % (serviceCheck, serviceCheckPort))
			logger.warning("Unable to reach %s:%s" % (serviceCheck, serviceCheckPort))

def getDSVersion():
	if checkInstall():
		if glb.forceMode:
			try:
				with open(glb.gmsVersion) as f:
					value = f.read().split('.')[0]
			except:
				return None
		else:
			with open(glb.gmsVersion) as f:
				value = f.read().split('.')[0]
		
		logger.info("Version: %s" % value)
		return int(value)

def setVariables():
	dsVersion = getDSVersion()
	# Depends on version 1.x or 2.x
	if checkInstall():
		if dsVersion >= glb.ds_1x:
			declareVariables2()
		else:
			declareVariables1()

def dsUpdate(repo):
	spinner = set_spinner()
	logger.info("Starting Mobility update using repository '%s'" % repo)
	print ("Refreshing repository..")
	logger.info("Refreshing repository..")
	cmd = "zypper --gpg-auto-import-keys ref -f %s" % repo
	logger.debug("Running command: %s" % cmd)
	out = util_subprocess(cmd)
	logger.info("Done refreshing")

	logger.info("Checking for repository updates..")
	cmd ="zypper lu -r %s" % repo
	logger.debug("Running command: %s" % cmd)
	out = util_subprocess(cmd)
	if 'No updates found' in out[0]:
		print ("\nMobility is already this version, or newer")
		logger.info('Unable to update mobility. Same version or newer')

		if askYesOrNo('List %s packages' % repo):
			cmd = "zypper pa -ir %s" % repo
			logger.debug("Running command: %s" % cmd)
			print (subprocess.Popen(cmd, shell=True).communicate()[0])
			print ()

			if askYesOrNo("Force install %s packages" % repo):
				print ("Force updating Mobility.. ", end='')
				logger.info('Force updating Mobility..')
				spinner.start(); time.sleep(.000001)
				time1 = time.time()
				cmd = "zypper --non-interactive install --force %s:" % repo
				logger.debug("Running command: %s" % cmd)
				out = util_subprocess(cmd)
				spinner.stop(); print ()
				time2 = time.time()
				logger.info("Foce update Mobility package complete")
				logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
				print ("\nPlease run 'sh %s/update.sh' to complete the upgrade" % glb.dirOptMobility)
			else: print ()
		else: print ()
	else:
		print ("Updating Mobility.. ", end='')
		logger.info('Updating Mobility started')
		spinner.start(); time.sleep(.000001)
		time1 = time.time()
		cmd = "zypper --non-interactive update --force -r %s" % repo
		logger.debug("Running command: %s" % cmd)
		out = util_subprocess(cmd, True)
		if out[1]:
			spinner.stop();print ()
			print ("Failed to update Mobility")
			logger.error("Failed to update Mobility")
			print (out[0])
			print (out[1])
			print ("Run the following commands to update manually:\n1. zypper update --force -r %s\n2. /opt/novell/datasync/update.sh\n" % repo)
			return

		spinner.stop(); print ()
		time2 = time.time()
		logger.info("Updating Mobility package complete")
		logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

		# Update config file
		dsVersion = getDSVersion()
		Config.read(glb.dsappSettings)
		Config.set('Misc', 'mobility.version', dsVersion)
		with open(glb.dsappSettings, 'wb') as cfgfile:
			logger.debug("Writing: [Misc] mobility.version = %s" % dsVersion)
			Config.write(cfgfile)

		# Update postgres settings
		print ("Updating postgres settings..")
		logger.info("Updating postgres settings..")
		cmd = "sed -i 's/shared_buffers = 32MB/shared_buffers = 512MB/g; s/#work_mem = 1MB/work_mem = 10MB/g; s/#log_temp_files = -1/log_temp_files = 0/g; s/max_fsm_pages = 204800/max_fsm_pages = 819200/g; s/#checkpoint_segments = 3/checkpoint_segments = 40/g' /var/lib/pgsql/data/postgresql.conf"
		out = util_subprocess(cmd)

		# Setting variables after upgrade (If going from 1.x to 2.x)
		setVariables()
		
		rcDS('stop')
		os.environ["FEEDBACK"] = ""
		os.environ["LOGGER"] = ""

		spinner2 = set_spinner()
		logger.info('Updating Mobility schema started')
		print ("Updating Mobility database schema.. ", end='')
		spinner2.start(); time.sleep(.000001)
		time1 = time.time()
		cmd = "python %s/common/lib/upgrade.pyc" % glb.dirOptMobility
		out = util_subprocess(cmd)
		spinner2.stop(); print ()
		time2 = time.time()
		logger.info("Updating Mobility schema complete")
		logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

		cmd ="rcpostgresql stop"
		out = util_subprocess(cmd, True)
		pids = get_pid(glb.python_Directory)
		for pid in pids:
			kill_pid(int(pid), 9)

		# Update config file
		dsVersion = getDSVersion()
		Config.read(glb.dsappSettings)
		Config.set('Misc', 'mobility.version', dsVersion)
		with open(glb.dsappSettings, 'wb') as cfgfile:
			logger.debug("Writing: [Misc] mobility.version = %s" % dsVersion)
			Config.write(cfgfile)

		cmd ="rcpostgresql start"
		out = util_subprocess(cmd, True)
		rcDS('start')

		with open(glb.dirOptMobility + '/version') as v:
			version = v.read()
		print ("\nMobility successfully updated to %s" % version)
		logger.info('Mobility successfully updated to %s' % version)


##################################################################################################
#	Start of RPM definitions
##################################################################################################
# Code used from: https://docs.fedoraproject.org/

# Global file descriptor for the callback.
rpmtsCallback_fd = None

def runCallback(reason, amount, total, key, client_data):
    global rpmtsCallback_fd
    if reason == rpm.RPMCALLBACK_INST_OPEN_FILE:
        rpmtsCallback_fd = os.open(key, os.O_RDONLY)
        return rpmtsCallback_fd
    elif reason == rpm.RPMCALLBACK_INST_START:
        os.close(rpmtsCallback_fd)

def checkCallback(ts, TagN, N, EVR, Flags):
    if TagN == rpm.RPMTAG_REQUIRENAME:
        prev = ""
    Nh = None

    if N[0] == '/':
        dbitag = 'basenames'
    else:
        dbitag = 'providename'

    # What do you need to do.
    if EVR:
        print ("Must find package [", N, "-", EVR, "]")
    else:
        print ("Must find file [", N, "]")

    if resolved:
        # ts.addIntall(h, h, 'i')
        return -1

    return 1

def readRpmHeader(ts, filename):
    """ Read an rpm header. """
    header = None
    try:
    	fd = os.open(filename, os.O_RDONLY)
    	header = ts.hdrFromFdno(fd)
    	os.close(fd)
    	return header
    except OSError:
    	logger.exception('Got an exception error:')
    	raise

def getRPMs():
	ts = rpm.TransactionSet()
	mi = ts.dbMatch()
	list = []
	logger.info("Obtaining list of system RPMs")
	time1 = time.time()
	for h in mi:
		list.append("%s-%s-%s" % (h['name'], h['version'], h['release']))
	time2 = time.time()
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	return list

def queue_getRPMs(que):
	que.put(getRPMs())

def findRPM(rpmName):
	ts = rpm.TransactionSet()
	mi = ts.dbMatch()
	list = []
	if mi:
		mi.pattern('name', rpm.RPMMIRE_GLOB, rpmName)
		for h in mi:
			list.append("%s-%s-%s" % (h['name'], h['version'], h['release']))
		return list

def checkRPM(rpmName):
	ts = rpm.TransactionSet()
	h = readRpmHeader(ts, rpmName)
	pkg_ds = h.dsOfHeader()
	for inst_h in ts.dbMatch('name', h['name']):
	    inst_ds = inst_h.dsOfHeader()
	    if pkg_ds.EVR() >= inst_ds.EVR():
	    	# rpmName is newer or same. OK to upgrade
	        return True
	    else:
	    	# rpmName is older. Do NOT overwrite
	        return False

def setupRPM(rpmName,flag='u'):
	ts = rpm.TransactionSet()
	h = readRpmHeader(ts, rpmName)
	ts.addInstall(h, rpmName, flag)

	# Set to not verify DSA signatures.
	ts.setVSFlags(-1)

	unresolved_dependencies = ts.check(checkCallback)

	if not unresolved_dependencies:
		ts.order()

		spinner = set_spinner()
		if flag == 'u':
			print ("This will update to:")
			log = 'Updating'
		elif flag == 'i':
			print ("This will install:")
			log = 'Installing'
		for te in ts:
			print ("%s-%s-%s" % (te.N(), te.V(), te.R()))
			logger.info("%s %s-%s-%s started" % (log, te.N(), te.V(), te.R()))
			break

		if flag == 'u':
			print ("\nUpdating.. ", end='')
		if flag == 'i':
			print ("\nInstalling.. ", end='')

		spinner.start(); time.sleep(.000001)
		ts.run(runCallback, 1)
		spinner.stop(); print ()
		if flag == 'u':
			print ("Update complete\n")
		elif flag == 'i':
			print ("Install complete\n")
		logger.info("%s %s-%s-%s complete" % (log, te.N(), te.V(), te.R()))
	else:
		print ("Error: Unresolved dependencies, transaction failed.")
		print (unresolved_dependencies)

def removeRPM(rpmName):
	ts = rpm.TransactionSet()
	ts.addErase(rpmName)

	# Set to not verify DSA signatures.
	ts.setVSFlags(-1)

	unresolved_dependencies = ts.check(checkCallback)

	if not unresolved_dependencies:
		ts.order()

		spinner = set_spinner()
		log = 'Uninstalling'
		for te in ts:
			name = '%s-%s-%s' % (te.N(), te.V(), te.R())
			logger.info("%s %s started" % (log, name))

		print ("\nUninstalling %s " % (name), end='')
		logger.info("Uninstalling %s" % name)
		spinner.start(); time.sleep(.000001)

		ts.run(runCallback, 1)
		spinner.stop(); print ()

		print ("Uninstall complete\n")
		logger.info("%s %s-%s-%s complete" % (log, te.N(), te.V(), te.R()))
	else:
		print ("Error: Unresolved dependencies, transaction failed.")
		print (unresolved_dependencies)

##################################################################################################
#	End of RPM definitions
##################################################################################################

def protect(msg, encode, path, host = None, key = None, skip=False):
# Code from GroupWise Mobility Service (GMS) datasync.util.
# Modified for dsapp
	result = None
	if host is None:
		if encode:
			result = base64.urlsafe_b64encode(os.popen('echo -n %s | openssl enc -aes-256-cbc -a -k `hostname -f`' % quote(msg)).read().rstrip())
		else:
			try:
				msg = base64.urlsafe_b64decode(msg)
			except:
				pass

			result = os.popen('echo %s | openssl enc -d -aes-256-cbc -a -k `hostname -f` 2>%s/decode_error_check' % (quote(msg),glb.dsapptmp)).read().rstrip()
	else:
		if encode:
			result = base64.urlsafe_b64encode(os.popen('echo -n %s | openssl enc -aes-256-cbc -a -k %s' % (quote(msg),host)).read().rstrip())
		else:
			try:
				msg = base64.urlsafe_b64decode(msg)
			except:
				pass

			result = os.popen('echo %s | openssl enc -d -aes-256-cbc -a -k %s 2>%s/decode_error_check' % (quote(msg),host,glb.dsapptmp)).read().rstrip()

	# Check for errors
	if os.path.isfile(glb.dsapptmp + '/decode_error_check') and os.stat(glb.dsapptmp + '/decode_error_check').st_size != 0 and path is not None:
		logger.error('bad decrypt - error decoding %s' % (path))

		if not skip:
			os.remove(glb.dsapptmp + '/decode_error_check')
			dsappExitError('bad decrypt - error decoding %s' % (path), exit=True, printMessage=True)
		else:
			return None
	elif result:
		return result
def encryptMSG(msg):
	result = base64.urlsafe_b64encode(os.popen('echo -n %s | openssl enc -aes-256-cbc -a -k `hostname -f`' % quote(msg)).read().rstrip())
	return result

def getEncrypted(msg, tree, pro_path, host = None):
	try:
		protected = xmlpath(pro_path, tree)
	except:
		pass

	if protected is None:
		return msg
	elif int(protected) == 1:
		return protect(msg, 1, None, host)
	elif int(protected) == 0:
		return msg

def getDecrypted(check_path, tree, pro_path, host=None, force=False):
	valueEmpty = xmlpath(check_path, tree)
	if valueEmpty is None:
		logger.debug("No value at %s" % check_path)
		return None
		
	try:
		protected = xmlpath(pro_path, tree)
	except:
		pass

	if protected is None:
		return xmlpath(check_path, tree)
	elif int(protected) == 1:
		return protect(xmlpath(check_path, tree), 0, check_path, host, skip=force)
	elif int(protected) == 0:
		return xmlpath(check_path,tree)

def isProtected(tree, pro_path):
	protected = xmlpath(pro_path, tree)
	logger.debug("Protected = %s" % protected)
	if protected is None:
		return False
	elif int(protected) == 1:
		return True
	elif int(protected) == 0:
		return False

def backup_file(source, dest):
	date_fmt = datetime.datetime.now().strftime('%X_%F')
	folder_name = source.split('/')[-2]
	dest = '%s/%s/%s' % (dest,date_fmt,folder_name)
	if os.path.isfile(source):
		if not os.path.exists(dest):
			os.makedirs(dest)
		logger.debug('Backing up %s to %s' % (source,dest))
		shutil.copy(source, dest)

def backup_config_files(list, fname=None):
	folder_name = None
	for path in list:
		if os.path.isfile(list[path]):
			if fname is not None:
				backup_file(list[path],'%s/%s' % (glb.dsappBackup,fname))
			else:
				backup_file(list[path],'%s' % (glb.dsappBackup))

def check_hostname(old_host, forceFix=False):
	new_host = os.popen('echo `hostname -f`').read().rstrip()
	logger.debug("Current hostname: %s" % new_host)
	logger.debug("Stored hostname: %s" % old_host)
	if old_host != new_host:
		if not forceFix:
			print ("Hostname %s does not match configured %s" % (new_host, old_host))
			logger.warning('Hostname %s does not match %s' % (new_host,old_host))
			if not sys.stdout.isatty():
				return False
		print ("This will fix encryption with old hostname '%s'" % old_host)
		if askYesOrNo('Run now'):
			update_xml_encrypt(old_host, new_host)
			Config.read(glb.dsappSettings)
			Config.set('Misc', 'hostname', new_host)
			with open(glb.dsappSettings, 'wb') as cfgfile:
				logger.debug("Writing: [Misc] hostname = %s" % new_host)
				Config.write(cfgfile)
			return True
		else:
			return False
	elif old_host == new_host and forceFix:
		print ("No difference in old and new hostname")
		logger.info(("No difference in old and new hostname"))
		return False
	elif old_host == new_host:
		return True

def update_xml_encrypt(old_host, new_host):
	# Attempt to get all encrypted in clear text using old_host
	before = {}
	logger.debug("Attempting to decrypt with hostname: %s" % old_host)
	before['smtp'] = getDecrypted('.//configengine/notification/smtpPassword', glb.XMLconfig['ceconf'], './/configengine/notification/protected', old_host)
	before['ldap'] = getDecrypted('.//configengine/ldap/login/password', glb.XMLconfig['ceconf'], './/configengine/ldap/login/protected', old_host)
	before['key'] = getDecrypted('.//settings/custom/trustedAppKey', glb.XMLconfig['gconf'], './/settings/custom/protected', old_host)
	before['ceconf_db'] = getDecrypted('.//configengine/database/password', glb.XMLconfig['ceconf'], './/configengine/database/protected', old_host)
	before['mconf_db'] = getDecrypted('.//settings/custom/dbpass', glb.XMLconfig['mconf'], './/settings/custom/protected', old_host)
	before['econf_db'] = getDecrypted('.//settings/database/password', glb.XMLconfig['econf'], './/settings/database/protected', old_host)
	
	after = {}
	logger.debug("Getting new encryption with hostname: %s" % new_host)
	after['smtp'] = getEncrypted(before['smtp'], glb.XMLconfig['ceconf'], './/configengine/notification/protected', new_host)
	after['ldap'] = getEncrypted(before['ldap'], glb.XMLconfig['ceconf'], './/configengine/ldap/login/protected', new_host)
	after['key'] = getEncrypted(before['key'], glb.XMLconfig['gconf'], './/settings/custom/protected', new_host)
	after['ceconf_db'] = getEncrypted(before['ceconf_db'], glb.XMLconfig['ceconf'], './/configengine/database/protected', new_host)
	after['mconf_db'] = getEncrypted(before['mconf_db'], glb.XMLconfig['mconf'], './/settings/custom/protected', new_host)
	after['econf_db'] = getEncrypted(before['econf_db'], glb.XMLconfig['econf'], './/settings/database/protected', new_host)
	
	# Backup XML files
	backup_config_files(glb.config_files, 'update_xml_encrypt')

	# Update the XMLs
	setXML('.//configengine/notification/smtpPassword', glb.XMLconfig['ceconf'], after['smtp'], glb.config_files['ceconf'])
	setXML('.//configengine/ldap/login/password', glb.XMLconfig['ceconf'], after['ldap'], glb.config_files['ceconf'])
	setXML('.//settings/custom/trustedAppKey', glb.XMLconfig['gconf'], after['key'], glb.config_files['gconf'])
	setXML('.//configengine/database/password', glb.XMLconfig['ceconf'], after['ceconf_db'], glb.config_files['ceconf'])
	setXML('.//settings/database/password', glb.XMLconfig['econf'], after['econf_db'], glb.config_files['econf'])
	setXML('.//settings/custom/dbpass', glb.XMLconfig['mconf'], after['mconf_db'], glb.config_files['mconf'])

	print ("Encryption has been updated in config files")
	logger.info("Encryption has been updated in config files")

def promptVerifyPath(path):
	if path is None or path is "":
		print ("Not a valid path")
		logger.warning("Not a valid path: %s" % path)
		return False
	if not os.path.exists(path):
		if askYesOrNo("Path does not exist, would you like to create it now"):
			logger.info('Creating folder: %s' % (path))
			os.makedirs(path)
		else:
			return False
	return True
	
def checkYaST():
	# Check if YaST is running
	results = False
	yast_runnning = get_pid('yast')
	if len(yast_runnning) <= 0:
		logger.debug("YaST not running")
		results = True

	for pid in yast_runnning:
		pid = int(pid)
		if check_pid(pid):
			print ('\nYaST is running. Close YaST before proceeding')
			if askYesOrNo('Attempt to close YaST now'):
				logger.info('Attempting to kill YaST [%s]' % (pid))
				kill_pid(pid)
				time.sleep(1)
				if check_pid(pid):
					logger.warning('Failed to kill YaST [%s]' % (pid))
					if askYesOrNo('Unable to close YaST. Force close YaST'):
						logger.info('Attempting to force kill YaST [%s]' % (pid))
						kill_pid(pid, 9)
						time.sleep(1)
						if not check_pid(pid):
							print('Failed to force close YaST. Aborting')
							logger.warning('Unable to force kill YaST. Aborting')
							results = False
						else:
							print ("Successfully force closed YaST")
							logger.info("Successfully force closed YaST")
							results = True
					else:
						results = False
			else:
				print ("Successfully closed YaST")
				logger.info("Successfully closed YaST")

	return results

#### Postgres Definitions #####

def checkPostgresql(report=True):
	try:
		conn = psycopg2.connect("dbname='postgres' user='%s' host='%s' password='%s'" % (glb.dbConfig['user'],glb.dbConfig['host'],glb.dbConfig['pass']))
		logger.info('Successfully connected to postgresql [user=%s,pass=%s]' % (glb.dbConfig['user'],"*" * len(glb.dbConfig['pass'])))
		conn.close()
	except:
		if report:
			dsappExitError(exit=False, printMessage=False)
		logger.error('Unable to connect to postgresql [user=%s,pass=%s]' % (glb.dbConfig['user'],"*" * len(glb.dbConfig['pass'])))
		return False
	return True

def checkDatabase(database):
	if (database,) not in listDatabases():
		logger.warning("Database %s does not exist" % database)
		return False
	try:
		conn = psycopg2.connect("dbname='%s' user='%s' host='%s' password='%s'" % (database, glb.dbConfig['user'],glb.dbConfig['host'],glb.dbConfig['pass']))
		logger.info('Successfully connected to %s database [user=%s,pass=%s]' % (database, glb.dbConfig['user'],"*" * len(glb.dbConfig['pass'])))
		conn.close()
	except:
		dsappExitError(exit=False, printMessage=False)
		logger.error('Unable to connect to %s database [user=%s,pass=%s]' % (database, glb.dbConfig['user'],"*" * len(glb.dbConfig['pass'])))
		return False
	return True

def getConn(database):
	# Assume connection is valid, as checkPostgresql is tested on startup
	try:
		conn = psycopg2.connect("dbname='%s' user='%s' host='%s' password='%s'" % (database, glb.dbConfig['user'],glb.dbConfig['host'],glb.dbConfig['pass']))
	except:
		return None
	conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
	return conn

def listDatabases():
	conn = getConn('postgres')
	cur = conn.cursor()
	cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
	data = cur.fetchall()
	cur.close()
	conn.close()
	logger.debug("Returning list of databases: %s" % data)
	return data
	
def dumpTable(database, tableName, targetSave):
	if not checkDatabase(database):
		return

	filePath = "%s/%s.sql" %(targetSave, tableName)
	if os.path.isfile(filePath):
		print ("%s already exists.\nCreated : %s" % (filePath, time.ctime(os.path.getctime(filePath))))
		logger.info("%s already exists. Created : %s" % (filePath, time.ctime(os.path.getctime(filePath))))
		if os.stat(filePath).st_size == 0:
			print ("WARNING: SQL file is empty!")
		if not askYesOrNo("Overwrite SQL file"):
			return

	logger.info("Dumping %s table from %s database to %s" % (tableName, database, filePath))
	cmd = "PGPASSWORD='%s' pg_dump --inserts -U %s %s -a -t '\"%s\"' > %s" % (glb.dbConfig['pass'], glb.dbConfig['user'], database, tableName, filePath)
	logger.debug("Running command: %s" % cmd)
	dump = subprocess.call(cmd, shell=True)

def dropDatabases():
	conn = getConn('postgres')
	cur = conn.cursor()
	databases = listDatabases()

	Config.read(glb.dsappSettings)
	mobile_version = Config.get('Misc', 'mobility.version')
	mobile_version = int(mobile_version)

	time1 = time.time()
	#Dropping Tables
	if ('datasync',) in databases:
		print ("Dropping datasync database")
		logger.info("Dropping databases started")
		try:
			cur.execute("DROP DATABASE datasync")
			logger.info('Dropped datasync database')
		except:
			print('Unable to drop datasync database')
			logger.error('Unable to drop datasync database')
			cur.close()
			conn.close()
			return

	if ('mobility',) in databases: 
		print ("Dropping mobility database")
		try:
			cur.execute("DROP DATABASE mobility")
			logger.info('Dropped mobility database')
		except:
			print('Unable to drop mobility database')
			logger.error('Unable to drop mobility database')
			cur.close()
			conn.close()
			return

	if mobile_version >= glb.ds_1x:
		if ('dsmonitor',) in databases:
			print ("Dropping dsmonitor database")
			try:
				cur.execute("DROP DATABASE IF EXISTS dsmonitor")
				logger.info('Dropped dsmonitor database')
			except:
				print('Unable to drop dsmonitor database')
				logger.error('Unable to drop dsmonitor database')
				cur.close()
				conn.close()
				return

	time2 = time.time()
	logger.info('Dropping databases complete')
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	cur.close()
	conn.close()

def dropSpecificDatabases(database):
	conn = getConn('postgres')
	cur = conn.cursor()

	try:
		cur.execute("DROP DATABASE %s" % database)
		logger.info('Dropped %s database' % database)
		cur.close()
		conn.close()
		return True
	except:
		print('Unable to drop %s database' % database)
		logger.error('Unable to drop %s database' % database)
		cur.close()
		conn.close()
		return False

def verify_clean_database():
	check = [('datasync',), ('mobility',), ('dsmonitor',)]
	conn = getConn('postgres')
	cur = conn.cursor()
	cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
	databases = cur.fetchall()

	for d in databases:
		if d in check:
			logger.info("Found database %s" % d)
			return False
	logger.info("No databases found")
	return True

def createDatabases():
	conn = getConn('postgres')
	cur = conn.cursor()

	Config.read(glb.dsappSettings)
	mobile_version = Config.get('Misc', 'mobility.version')
	mobile_version = int(mobile_version)

	print('Starting database creation..')
	logger.info('Starting database creation..')
	time1 = time.time()

	cur.execute("CREATE DATABASE datasync")
	print("Datasync database done")
	logger.info('datasync database created')
	cur.execute("CREATE DATABASE mobility")
	print("Mobility database done")
	logger.info('mobility database created')
	if mobile_version >= glb.ds_1x:
		cur.execute("CREATE DATABASE dsmonitor")
		print("DSmonitor database done")
		logger.info('dsmonitor database created')
	cur.close()
	conn.close()

	# Opening connection with datasync database
	print('\nExtending schema..')
	logger.info('Extending schema in databases')
	conn = getConn('datasync')
	cur = conn.cursor()
	cur.execute(open(glb.dirOptMobility + '/common/sql/postgresql/configengine.sql', 'r').read())
	cur.execute(open(glb.dirOptMobility + '/common/sql/postgresql/datasync.sql', 'r').read())
	print('Extending schema on datasync done')
	logger.info('Extending schema on datasync complete')

	DATE = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	with open(glb.gmsVersion, 'r') as f:
		VERSION = f.read()
	command = {'DATE': DATE, 'VERSION': VERSION}
	INSERT = "INSERT INTO services (service, initial_version, initial_timestamp, previous_version, previous_timestamp, service_version, service_timestamp) VALUES ('Mobility','', '%(DATE)s', '%(VERSION)s', '%(DATE)s', '%(VERSION)s', '%(DATE)s');" % command
	cur.execute(INSERT)
	print("Added service record")
	logger.info('Added service record to datasync')
	cur.close()
	conn.close()

	# Opening connection with mobility database
	conn = getConn('mobility')
	cur = conn.cursor()
	cur.execute(open(glb.dirOptMobility + '/syncengine/connectors/mobility/mobility_pgsql.sql', 'r').read())
	print('Extending schema on mobility done')
	logger.info('Extending schema on mobility complete')
	cur.close()
	conn.close()

	if mobile_version >= glb.ds_1x:
		conn = getConn('dsmonitor')
		cur = conn.cursor()
		cur.execute(open(glb.dirOptMobility + '/monitorengine/sql/monitor.sql', 'r').read())
		print('Extending schema on dsmonitor done')
		logger.info('Extending schema on dsmonitor complete')
		cur.close()
		conn.close()
	time2 = time.time()
	print('\nDatabase creation done')
	logger.info('Creating databases complete')
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

def createSpecificDatabases(database):
	conn = getConn('postgres')
	cur = conn.cursor()
	cur.execute("CREATE DATABASE %s" % database)
	cur.close()
	conn.close()

###### End of Postgresql Definitions ########

def cuso(op = 'everything'):
	print ('Running CUSO..\n')
	logger.info('Starting CUSO')
	time1 = time.time()
	continue_cleanup = False
	if op == 'user':
		dumpTable('datasync', 'membershipCache', glb.dsappdata)
		print()
		dumpTable('datasync', 'targets', glb.dsappdata)
		print()

	# Validate SQL exists, and has some data
	if op == 'user':
		if not os.path.isfile(glb.dsappdata +'/targets.sql') and not os.path.isfile(glb.dsappdata +'/membershipCache.sql'):
			print ("\nCUSO pre-check: Unable to find SQL backup")
			logger.warning("Unable to find user SQL backup")
			return
		else:
			if os.stat(glb.dsappdata +'/targets.sql').st_size == 0:
				print("\nCUSO pre-check: SQL backup file is empty")
				logger.warning("targets.sql backup file is empty")
				return

	# Dropping Databases
	logger.info("Restarting postgres..")
	p = subprocess.Popen(['rcpostgresql', 'restart'], stdout=subprocess.PIPE,  stderr=subprocess.PIPE)
	p.wait()
	if checkPostgresql(report=False):
		dropDatabases()
	else:
		print("Postgres unable to restart")
		logger.info("Postgres unable to restart")
		return

	# Check if database is clean
	if verify_clean_database():
		# Recreate tables switch
		if op != 'uninstall':
			# Recreating Databases
			createDatabases()
			if op == 'user':
				# Repopulating targets and membershipCache
				conn = getConn('datasync')
				cur = conn.cursor()
				cur.execute(open(glb.dsappdata +'/targets.sql', 'r').read())
				logger.info('Imported targets.sql into datasync database')
				cur.execute(open(glb.dsappdata +'/membershipCache.sql', 'r').read())
				logger.info('Imported membershipCache.sql into datasync database')
				cur.close()
				conn.close()
			continue_cleanup = True

		#Check if uninstall parameter was passed in - Force uninstall
		elif op == 'uninstall':
			# rcpostgresql stop; killall -9 postgres &>/dev/null; killall -9 python &>/dev/null;
			rpms = findRPM('datasync-*')
			for rpm in rpms:
				removeRPM(rpm)
			removeRPM(findRPM('postgresql')[0])
			if glb.dsappversion > 194:
				removeRPM('dsapp')

			# Copy logs to /tmp before removing /opt/novell/datasync/
			if os.path.isfile(glb.dsappLogs) and os.path.exists('/tmp/'):
				logger.info('Copying %s to /tmp/' % (glb.dsappLogs))
				shutil.copy(glb.dsappLogs, '/tmp/')

			folders = [glb.dirPGSQL, glb.dirEtcMobility, glb.dirVarMobility, log, glb.dirOptMobility]
			for folder in folders:
				if os.path.exists(folder):
					shutil.rmtree(folder)
					logger.info('Removing %s' % folder)

			print("Mobility uninstalled.")
			eContinue()
			sys.exit(0)

	else:
		if askYesOrNo('Continue with cleanup'):
			continue_cleanup = True
		else:
			return

	if continue_cleanup:
		# vacuum & index
		vacuumDB()
		indexDB()

		spinner = set_spinner()
		print('Cleaning up attachments ', end='')
		spinner.start(); time.sleep(.000001)
		removeAllFolders(glb.dirVarMobility + '/syncengine/attachments')
		removeAllFolders(glb.dirVarMobility + '/mobility/attachments')
		spinner.stop(); print()

	time2 = time.time()
	print('CUSO complete')
	logger.info('CUSO complete')
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

def registerDS():
	Config.read(glb.dsappSettings)
	osVersion = Config.getint('Misc', 'sles.version')
	if osVersion >= 12:
		print("Registration for SLES %s coming soon" % osVersion)
		logger.info("Registration for SLES %s coming soon" % osVersion)
		return
	#Obtain Registration/Activation Code and Email Address
	try:
		reg = raw_input("Registration Code: ")
		email = raw_input("Email Address: ")
		if reg == '' or email == '':
			print("Invalid input")
			raise
	except:
		print()
	else:
		time1 = time.time()
		spinner = set_spinner()
		print("Running registration.. ", end='')
		logger.info('Starting mobility registration')
		spinner.start(); time.sleep(.000001)

		output,err = subprocess.Popen(['suse_register', '-a', 'regcode-mobility=%s' % reg, '-a', 'email=%s' % email, '-L', '/root/.suse_register.log', '-d', '3'], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
		time2 = time.time()
		spinner.stop(); print()
		if err != '':
		    print(textwrap.fill("\n\nThe code or email address you provided appear to be invalid or there is trouble contacting registration servers\n", int(WINDOW_SIZE[1])).lstrip())
		    logger.warning('Failed to register mobility')
		else:
			print("\nYour Mobility product has been successfully activated.")
			logger.info('Mobility successfully registered')
			logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

def cleanLog():
	Config.read(glb.dsappSettings)
	logMaxage = Config.get('Log', 'datasync.log.maxage')
	dsappLogMaxage = Config.get('Log', 'dsapp.log.maxage')

	datasyncBanner()
	if askYesOrNo("Clean out log files"):
		print("Cleaning logs..")
		logger.info("Cleaning logs..")
		removeAllFiles(glb.log + '/connectors')
		removeAllFiles(glb.log + '/syncengine')
		if askYesOrNo("\nPrevent future disk space hogging, set log maxage to %s" % logMaxage):
			logger.info('Setting max log days to %s' % logMaxage)
			os.popen("sed -i 's|maxage.*|maxage %s|g' /etc/logrotate.d/datasync-*" % logMaxage).read()
			os.popen("sed -i 's|maxage.*|maxage %s|g' /etc/logrotate.d/dsapp" % dsappLogMaxage).read()
			print('Completed setting log maxage to %s' % logMaxage)
			logger.info('Completed setting log maxage to %s' % logMaxage)

def rcDS(status, op=None, show_spinner=True, show_print=True):
	setVariables()
	dsVersion = getDSVersion()
	spinner = set_spinner()

	# # Get list of datasync scripts in /etc/init.d/ dynamically 
	# datasync_scripts = []
	# for file in os.listdir(glb.initScripts):
	# 	if INIT_NAME in file:
	# 		datasync_scripts.append(file)

	# Hard code the datasync_scripts (with the correct order)
	datasync_scripts = ['datasync-configengine', 'datasync-syncengine', 'datasync-connectors', 'datasync-webadmin']
	if dsVersion >= glb.ds_1x:
		datasync_scripts.append('datasync-monitorengine')

	if status == "start" and op == None:
		if show_print:
			print('Starting Mobility.. ', end='')
		logger.info("Starting Mobility agents..")
		if show_spinner:
			spinner.start()
			time.sleep(.000001)
		for agent in datasync_scripts:
			cmd = '%s%s start' % (glb.initScripts, agent)
			logger.debug("Running '%s'" % cmd)
			out = util_subprocess(cmd, True)
			if out[1] and 'redirecting to system' not in out[1]:
				logger.error("Problem running '%s'" % cmd)
		cmd = 'rccron start'
		logger.debug("Running '%s'" % cmd)
		out = util_subprocess(cmd, True)
		if out[1] and 'redirecting to system' not in out[1]:
			logger.error("Problem running '%s'" % cmd)
		if show_spinner:
			spinner.stop()
			print()

	elif status == "start" and op == "nocron":
		if show_print:
			print('Starting Mobility.. ', end='')
		logger.info("Starting Mobility agents..")
		if show_spinner:
			spinner.start()
			time.sleep(.000001)
		for agent in datasync_scripts:
			cmd = '%s%s start' % (glb.initScripts, agent)
			logger.debug("Running '%s'" % cmd)
			out = util_subprocess(cmd, True)
			if out[1] and 'redirecting to system' not in out[1]:
				logger.error("Problem running '%s'" % cmd)
		if show_spinner:
			spinner.stop()
			print()

	elif status == "stop" and op == None:
		pids = get_pid(glb.python_Directory)
		if show_print:
			print('Stopping Mobility.. ', end='')
		logger.info("Stopping Mobility agents..")
		if show_spinner:
			spinner.start()
			time.sleep(.000001)
		for agent in datasync_scripts:
			cmd = '%s%s stop' % (glb.initScripts, agent)
			logger.debug("Running '%s'" % cmd)
			out = util_subprocess(cmd, True)
			if out[1] and 'redirecting to system' not in out[1]:
				logger.error("Problem running '%s'" % cmd)
		cmd = 'rccron stop'
		logger.debug("Running '%s'" % cmd)
		out = util_subprocess(cmd, True)
		if out[1] and 'redirecting to system' not in out[1]:
			logger.error("Problem running '%s'" % cmd)
		pids = get_pid(glb.python_Directory)
		cpids = get_pid('cron')
		for pid in pids:
			kill_pid(int(pid), 9)
		for pid in cpids:
			kill_pid(int(pid))
		if show_spinner:
			spinner.stop()
			print()

	elif status == "stop" and op == "nocron":
		if show_print:
			print('Stopping Mobility.. ', end='')
		logger.info("Stopping Mobility agents..")
		if show_spinner:
			spinner.start()
			time.sleep(.000001)
		for agent in datasync_scripts:
			cmd = '%s%s stop' % (glb.initScripts, agent)
			logger.debug("Running '%s'" % cmd)
			out = util_subprocess(cmd, True)
			if out[1] and 'redirecting to system' not in out[1]:
				logger.error("Problem running '%s'" % cmd)
		pids = get_pid(glb.python_Directory)
		for pid in pids:
			kill_pid(int(pid), 9)
		if show_spinner:
			spinner.stop()
			print()

	elif status == "restart" and op == None:
		if show_print:
			print('Restarting Mobility.. ', end='')
		logger.info("Stopping Mobility agents..")
		if show_spinner:
			spinner.start()
			time.sleep(.000001)
		for agent in datasync_scripts:
			cmd = '%s%s stop' % (glb.initScripts, agent)
			logger.debug("Running '%s'" % cmd)
			out = util_subprocess(cmd, True)
			if out[1] and 'redirecting to system' not in out[1]:
				logger.error("Problem running '%s'" % cmd)
		cmd = 'rccron stop'
		logger.debug("Running '%s'" % cmd)
		out = util_subprocess(cmd, True)
		if out[1] and 'redirecting to system' not in out[1]:
			logger.error("Problem running '%s'" % cmd)

		pids = get_pid(glb.python_Directory)
		cpids = get_pid('cron')
		for pid in pids:
			kill_pid(int(pid), 9)
		for pid in cpids:
			kill_pid(int(pid))

		logger.info("Starting Mobility agents..")
		for agent in datasync_scripts:
			cmd = '%s%s start' % (glb.initScripts, agent)
			logger.debug("Running '%s'" % cmd)
			out = util_subprocess(cmd, True)
			if out[1] and 'redirecting to system' not in out[1]:
				logger.error("Problem running '%s'" % cmd)
		cmd = 'rccron start'
		logger.debug("Running '%s'" % cmd)
		out = util_subprocess(cmd, True)
		if out[1] and 'redirecting to system' not in out[1]:
			logger.error("Problem running '%s'" % cmd)
		if show_spinner:
			spinner.stop()
			print()

def verifyUserMobilityDB(userConfig):
	# Check if user exists in mobility database
	logger.info('Checking for %s in mobility database' % userConfig['name'])
	name = {'user': userConfig['name']}
	conn = getConn('mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select distinct userid from users where userid ~* '(\\\\m%(user)s[.|,].*)$' OR userid ilike '%(user)s' OR name ilike '%(user)s'" % name)
	validUser = cur.fetchall()
	cur.close()
	conn.close()
	for row in validUser:
		if row['userid'] != "":
			logger.debug("Found '%s' in mobility database" % row['userid'])
			userConfig['mName'] = row['userid']
			return True
	logger.warning("'%s' not found in mobility database" % userConfig['name'])
	userConfig['mName'] = None
	return False

def verifyUserDataSyncDB(userConfig):
	# Check if user exists in datasync database
	logger.info('Checking for %s in datasync database' % userConfig['name'])
	name = {'user': userConfig['name']}
	conn = getConn('datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select distinct dn,\"targetType\" from targets where (\"dn\" ~* '(\\\\m%(user)s[.|,].*)$' OR dn ilike '%(user)s' OR \"targetName\" ilike '%(user)s') AND disabled='0'" % name)
	validUser = cur.fetchall()
	cur.close()
	conn.close()
	for row in validUser:
		if row['dn'] != "":
			logger.debug("Found '%s' in datasync database" % row['dn'])
			userConfig['dName'] = row['dn']
			userConfig['type'] = row['targetType']
			return True
	logger.warning("'%s' not found in datasync database "% userConfig['name'])
	userConfig['dName'] = None
	userConfig['type'] = None
	return False

def get_username(userConfig_List):
	with open(glb.dsappConf + '/special_char.cfg', 'r') as f:
		invalid = f.read().splitlines()
	del invalid[0] # Removes comment from list
	username = ""
	# Prompt user for username
	datasyncBanner()
	print ("Enter 'q' to cancel")
	while username == "":
		username = raw_input("User/Group ID: ")
		logger.info("Input: %s" % username)
		if username == 'q' or username == 'Q':
			userConfig = {'name': None}
			userConfig_List.append(userConfig)
			return False
		elif username in invalid:
			if not askYesOrNo("Invalid input. Try again"):
				userConfig = {'name': None}
				userConfig_List.append(userConfig)
				return False
			else:
				username = ""
		elif username == "":
			if not askYesOrNo("No input. Try again"):
				userConfig = {'name': None}
				userConfig_List.append(userConfig)
				return False

	userList = username.split(',')
	for name in userList:
		if name.strip() is None or len(name.strip()) == 0:
			userConfig = {'name': None}
			userConfig_List.append(userConfig)
		else:
			# userConfig = {'name': name.strip()} ## Strip space off the end?
			userConfig = {'name': name.lstrip()}
			userConfig_List.append(userConfig)

	return True

def verifyUser():
	userConfig_List = []

	# Return a number based on conditions 
	get_username(userConfig_List)
	for userConfig in userConfig_List:
		if userConfig['name'] is None:
			userConfig['mName'] = None
			userConfig['type'] = None
			userConfig['dName'] = None
			userConfig['verify'] = None
		# return userConfig_List
		else:

			# Calculate verifyCount based on where user was found
			verifyCount = 0
			# 0 = no user found ; 2 = datasync only ; 1 = mobility only ; 3 = both database

			if verifyUserDataSyncDB(userConfig):
				verifyCount += 2
			if userConfig['type'] != 'group':
				if verifyUserMobilityDB(userConfig):
					verifyCount += 1
			else:
				logger.debug("Skipping verifyUserMobilityDB. Type='%s'" % userConfig['type'])

			userConfig['verify'] = verifyCount
			if userConfig['type'] != 'group':
				userConfig = getApplicationNames(userConfig)
			else:
				userConfig['mAppName'] = None
				userConfig['gAppName'] = None

	datasyncBanner()
	return userConfig_List

def buildUserDBArray(userConfig_list):
	userArray = dict()
	default = []
	mobile = []
	mapping = []
	users = []

	for user in userConfig_list:
		if user['name'] is not None:
			users.append(user['name'])
			default.append('\\y%s\\y' % user['name'])
			mobile.append('\\y%s\\y' % user['name'])
			mapping.append('\\y%s\\y' % user['name'])
			mapping.append('(sourceName>)(\\y%s\\y)(</sourceName>)' % user['dName'])
		if user['dName'] is not None:
			default.append(user['dName'])
			mobile.append(user['dName'])
			mapping.append('(sourceDN>)(\\y%s\\y)(</sourceDN>)' % user['dName'])
		if user['mAppName'] is not None:
			if '\\y%s\\y' % user['gAppName'] not in default:
				default.append('\\y%s\\y' % user['gAppName'])
		if user['gAppName'] is not None:
			if '\\y%s\\y' % user['mAppName'] not in default:
				default.append('\\y%s\\y' % user['mAppName'])

	# Get GUIDs for users in mobility database
	conn = getConn('mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select guid from users where userid ~* ANY(%s)", (default,))
	guids = cur.fetchall()
	for guid in guids:
		mobile.append(guid['guid'])

	userArray['users'] = users
	userArray['mobile'] = mobile
	userArray['default'] = default
	userArray['mapping'] = mapping

	logger.debug("userArray: %s" % userArray)
	return userArray

def confirm_user(userConfig, database = None):
	if userConfig['name'] == None:
		return False
	if database == 1:
		return True
	elif database == 'mobility' and userConfig['verify'] == 2:
		print ("'%s' not found in Mobility" % userConfig['name'])
		return False
	elif database == 'datasync' and userConfig['verify'] == 1:
		print ("'%s' not found in Mobility" % userConfig['name'])
		return False
	if userConfig['verify'] == 0:
		print ("'%s' not found in Mobility" % userConfig['name'])
		return False
	return True

def monitor_command(command, refresh):
	clear()
	conn = getConn('mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

	clearLine = "\033[1J" + "\033[H"
	states = {'1': 'Initial Sync   ', '2': 'Synced         ', '3': 'Syncing-Days+  ', '5': 'Failed         ', '6':'Delete         ', '7': 'Re-Init        ', '9': 'Sync Validate  ', '11': 'Requesting Init', '12': 'Requesting More'}
	logger.info('Starting monitor')
	logger.debug("Starting monitor with command: '%s'" % command)
	try:
		while True:
			cur.execute(command)
			monitor = cur.fetchall()
			print ('  State              |  User ID                        [<Ctrl + c> to exit]')
			print('---------------------+----------------------------')
			for row in monitor:
				print('  ' + states[row['state']] + '    |  ' + row['userid'])
			time.sleep(refresh)
			sys.stdout.write(clearLine)
	except KeyboardInterrupt:
		logger.info('Ending monitor')

	clear()
	cur.close()
	conn.close()

def monitor_syncing_users(refresh = 1):
	command = "SELECT state,userID FROM users WHERE state !='2'"
	monitor_command(command, refresh)

def monitorUser(userList=None, refresh=1):
	if userList is None:
		userConfig_List = verifyUser()

	if userList is None:
		userList = []
		for userConfig in userConfig_List:
			if confirm_user(userConfig, 'mobility'):
				userList.append('%%%s%%' % userConfig['mName'])

	if len(userList) > 0:
		command = "SELECT state,userID FROM users WHERE userid ilike any(array%s)" % userList
		monitor_command(command, refresh)
		return
	else:
		print(); eContinue()


def setUserState(state):
	userList = []
	userConfig_List = verifyUser()
	if len(userConfig_List) == 1:
		if userConfig_List[0]['name'] is None:
			return

	for userConfig in userConfig_List:
		if confirm_user(userConfig, 'mobility'):
			userList.append('%%%s%%' % userConfig['mName'])

	if len(userList) > 0:	
		cmd = "UPDATE users SET state = '%s' WHERE userid ilike any(array%s)" % (state, userList)

		conn = getConn('mobility')
		cur = conn.cursor()
		cur.execute(cmd)
		logger.debug("Running PSQL command:\n%s" % cmd)
		cur.close()
		conn.close()

		logger.info("Set '%s' to state %s" % (userList, state))
		monitorUser(userList)
		return

	print(); eContinue()
	

def file_mCleanup(filePath, fileCount):
	date = datetime.datetime.now().strftime("%H:%M:%S on %b %d, %Y")
	count = 0
	if os.path.isfile(filePath):
		with open(filePath, 'r') as f:
			lines = f.read().splitlines()
		with open(glb.dsappLogs + '/mCleanup.log', 'a') as f:
			f.write("\n%s\n------- Removing %s attachments -------\n" % (date, fileCount))
			for i in xrange(len(lines)):
				removeF = glb.mAttach + filestoreIdToPath.hashFileStoreID(lines[i])
				try:
					os.remove(removeF)
					f.write("Removed '%s'\n" % removeF)
					count += 1
				except OSError:
					f.write("Warning: file %s not found\n" % removeF)

			f.write("------- Complete : %s files removed -------\n" % count)

		os.remove(filePath)
		os.remove(glb.dsappConf + '/fileIDs.dsapp')

def file_mCleanup_run(count):
	print ("Removing attachments..")
	logger.info("Removing %s attachments in background process" % count)
	# Clean up fileIDs in detached process
	filePath = glb.dsappConf + '/uniq-fileIDs.dsapp'
	p = Process(target=file_mCleanup, args=(filePath, count,))
	p.start()

def mCleanup(userArray, fileCleanupNow=True):
	print ("\nMobility database cleanup:")
	spinner = set_spinner()
	uGuid = ""
	
	conn = getConn('mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

	# print ("Removing %s attachment maps from mobility.." % userConfig['name'])
	print ("Removing attachment maps from mobility for users(s): %s" % ', '.join(userArray['users']))
	logger.info("Removing attachment maps from mobility for users(s): %s" % ', '.join(userArray['users']))

	# Delete attachmentmaps
	cur.execute("delete from attachmentmaps where userid ~* ANY(%s)", (userArray['mobile'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	# Get filestoreIDs that are safe to delete
	print ("Obtaining list of file store IDs to remove..")
	logger.info("Obtaining list of filestoreid to remove..")
	cur.execute("SELECT filestoreid FROM attachments LEFT OUTER JOIN attachmentmaps ON attachments.attachmentid=attachmentmaps.attachmentid WHERE attachmentmaps.attachmentid IS NULL")
	fileID = cur.fetchall()

	# Write fileIDs to a file
	with open(glb.dsappConf + '/fileIDs.dsapp', 'a') as f:
		for line in fileID:
			f.write(line['filestoreid']  + '\n')

	print ("Removing user(s) from mobility database: %s " % ', '.join(userArray['users']), end='')
	logger.info("Removing user(s) from mobility database: %s" % ', '.join(userArray['users']))
	spinner.start(); time.sleep(.000001)
	time1 = time.time()

	# clean tables with users guid
	cur.execute("DELETE from foldermaps where deviceid IN (select deviceid from devices where userid ~* ANY(%s))", (userArray['mobile'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	cur.execute("DELETE from deviceimages where userid ~* ANY(%s)", (userArray['mobile'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	cur.execute("DELETE from syncevents where userid ~* ANY(%s)", (userArray['mobile'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	cur.execute("DELETE from deviceevents where userid ~* ANY(%s)", (userArray['mobile'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	cur.execute("DELETE from devices where userid ~* ANY(%s)", (userArray['mobile'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	cur.execute("DELETE from users where guid ~* ANY(%s)", (userArray['mobile'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	cur.execute("DELETE from attachments where attachmentid IN (select attachmentid from attachmentmaps where objectid in (select objectid from deviceimages where userid ~* ANY(%s)))", (userArray['mobile'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	cur.execute("DELETE from attachments where filestoreid IN (SELECT filestoreid FROM attachments LEFT OUTER JOIN attachmentmaps ON attachments.attachmentid=attachmentmaps.attachmentid WHERE attachmentmaps.attachmentid IS NULL)")
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	spinner.stop(); print()
	cur.close()
	conn.close()

	# Remove duplicate fileIDs
	count = 0
	lines_seen = set()
	outfile = open(glb.dsappConf + '/uniq-fileIDs.dsapp', 'w')
	if os.path.isfile(glb.dsappConf + '/fileIDs.dsapp'):
		spinner = set_spinner()
		print ("Creating list of files to remove.. ", end='')
		logger.debug("Remove any duplicates fileIDs")
		spinner.start(); time.sleep(.000001)
		for line in open(glb.dsappConf + '/fileIDs.dsapp', 'r'):
			if line not in lines_seen: # No duplicates
				outfile.write(line)
				lines_seen.add(line)
				count += 1
		outfile.close()
		spinner.stop(); print();time.sleep(.000001)

	if fileCleanupNow:
		file_mCleanup_run(count)

	time2 = time.time()
	logger.info("Removal complete for user(s): %s" % ', '.join(userArray['users']))
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

	if not fileCleanupNow:
		return count

def dCleanup(userArray):
	print ("\nDatasync database cleanup:")
	spinner = set_spinner()

	print ("Removing user(s) from datasync database: %s " % ', '.join(userArray['users']), end='')
	logger.info("Removing user(s) from datasync database: %s" % ', '.join(userArray['users']))

	# Delete objectMappings, cache, membershipCache, folderMappings, and targets from datasync DB
	conn = getConn('datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

	spinner.start(); time.sleep(.000001)
	time1 = time.time()

	# cmd = "DELETE FROM \"objectMappings\" WHERE \"objectID\" IN (SELECT \"objectID\" FROM \"objectMappings\" WHERE \"objectID\" ilike '%%|%s' OR \"objectID\" ilike '%%|%s' OR \"objectID\" ilike '%%|%s')"
	cur.execute("DELETE FROM \"objectMappings\" WHERE \"objectID\" ~* ANY(%s)", (userArray['default'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	# cmd = "DELETE FROM consumerevents WHERE edata ilike '%%<sourceName>%s</sourceName>%%' OR edata ilike '%%<sourceName>%s</sourceName>%%' OR edata ilike '%%<sourceDN>%s</sourceDN>%%' OR edata ilike '%%<sourceDN>%s</sourceDN>%%'" % (psqlAppNameG, psqlAppNameM, psqlAppNameG, psqlAppNameM)
	cur.execute("DELETE FROM consumerevents WHERE edata ~* ANY(%s)", (userArray['mapping'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	# cmd = "DELETE FROM \"folderMappings\" WHERE \"targetDN\" ~* '(\\\\m%s[.|,].*)$' OR \"targetDN\" ilike '%s'" % (uUser, uUser)
	cur.execute("DELETE FROM \"folderMappings\" WHERE \"targetDN\" ~* ANY(%s)", (userArray['default'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	# cmd = "DELETE FROM cache WHERE \"sourceDN\" ~* '(\\\\m%s[.|,].*)$' OR \"sourceDN\" ilike '%s'" % (uUser, uUser)
	cur.execute("DELETE FROM cache WHERE \"sourceDN\" ~* ANY(%s)", (userArray['default'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)
	
	# cmd = "DELETE FROM \"membershipCache\" WHERE  groupdn ~* ANY(%s) OR memberdn ~* ANY(%s)", (userArray['default'],userArray['default'],))
	cur.execute("DELETE FROM \"membershipCache\" WHERE  groupdn ~* ANY(%s) OR memberdn ~* ANY(%s)", (userArray['default'],userArray['default'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)
	
	# cmd = "DELETE FROM targets WHERE dn ~* '(\\\\m%s[.|,].*)$' OR dn ilike '%s' OR \"targetName\" ilike '%s'" % (uUser, userConfig['name'], userConfig['name'])
	cur.execute("DELETE FROM targets WHERE dn ~* ANY(%s) OR \"targetName\" ~* ANY(%s)", (userArray['default'],userArray['default'],))
	logger.debug("Query: %s" % cur.query)
	logger.debug("Results: %s" % cur.statusmessage)

	time2 = time.time()
	logger.info("Removal complete for user(s): %s" % ', '.join(userArray['users']))
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	spinner.stop(); print()

	cur.close()
	conn.close()

def remove_user(op = None):
	# Pass in 1 for op to skip user database check in confirm_user()

	datasyncBanner()
	if op == 1:
		userArray = buildUserDBArray(verifyUser())
		if len(userArray['users']) == 1:
			if userArray['users'][0] is None:
				return

		logger.debug("Skipping user database check")
		fileClean = False
		count = 0

		if len(userArray['users']) > 1:
			if askYesOrNo("Remove all users/groups from datasync database"):
				dCleanup(userArray)
			print()
			if askYesOrNo("Remove all users from mobility database"):
				count += mCleanup(userArray, fileCleanupNow=False)
				fileClean = True
			print()
		else:
			if askYesOrNo("Remove %s from datasync database" % userArray['users'][0]):
				dCleanup(userArray)
			print()
			if askYesOrNo("Remove %s from mobility database" % userArray['users'][0]):
				count += mCleanup(userArray, fileCleanupNow=False)
				fileClean = True
			print()

		# Run file cleanup after ALL users have been removed
		if fileClean:
			file_mCleanup_run(count)

	elif op == None:
		userConfig_List = verifyUser()
		if len(userConfig_List) == 1:
			if userConfig_List[0]['name'] is None:
				return
				
		userConfig = userConfig_List[0]
		logger.debug("Checking user in database")
		if confirm_user(userConfig):

			# Set user to delete
			conn = getConn('datasync')
			cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
			cur.execute("update targets set disabled='3' where dn='%s'" % userConfig['dName'])
			logger.debug("Set %s state to 3" % userConfig['dName'])
			cur.close()
			conn.close()

			# Restart configengine
			print ("Restarting configengine..")
			logger.info("Restarting the configengine")
			cmd = 'rcdatasync-configengine restart'
			r = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
			r.wait()

			# Monitor mobility database for user to delete
			conn = getConn('mobility')
			cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

			print ("Cleaning up databases..")
			logger.info("Cleaning up database..")
			loop = True
			while loop:
				cur.execute("select state from users where userid='%s'" % userConfig['mName'])
				data = cur.fetchall()
				for row in data:
					if len(row) != '1':
						loop = False
				time.sleep(2)
			cur.close()
			conn.close()
			logger.info("Cleanup complete. Running force cleanup")

			userArry = buildUserDBArray(userConfig_List)

			dCleanup(userArry)
			print()
			mCleanup(userArry)
			print()

	eContinue()

def addGroup():
	conn = getConn('datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

	datasyncBanner()
	ldapGroupMembership = dict()
	member_and_group = []

	logger.info("Obtaining all groups from Mobility")
	cur.execute("select distinct dn from targets where \"targetType\"='group' AND dn ilike 'cn=%%'")
	ldapGroups = cur.fetchall()

	group_and_users = dict()
	print ("\nMobility Group(s):")
	for row in ldapGroups:
		print (row['dn'])

	print ("\nGroup Membership:")
	for group in ldapGroups:
		if glb.ldapConfig['secure'] == 'false':
			cmd = "/usr/bin/ldapsearch -x -H ldap://%s:%s -D '%s' -w '%s' -l 5 -b '%s' -s base | grep 'member:' | cut -f2 -d ' '" % (glb.ldapConfig['host'], glb.ldapConfig['port'], glb.ldapConfig['login'], glb.ldapConfig['pass'], group['dn'])
		elif glb.ldapConfig['secure'] == 'true':
			cmd = "/usr/bin/ldapsearch -x -H ldaps://%s:%s -D '%s' -w '%s' -l 5 -b '%s' -s base | grep 'member:' | cut -f2 -d ' '" % (glb.ldapConfig['host'], glb.ldapConfig['port'], glb.ldapConfig['login'], glb.ldapConfig['pass'], group['dn'])

		try:
			ldapGroupMembership[group['dn']] = os.popen(cmd).read().strip().split('\n')
		except:
			pass

	# build memberdn,groupdn list
	if len(ldapGroupMembership) >= 1:
		for group in ldapGroupMembership:
			for member in ldapGroupMembership[group]:
				member_and_group.append('"%s","%s"' % (member.strip(), group.strip()))

		# print memberdn, groupdn list & create list to import
		with open(glb.dsapptmp + '/ldapGroupMembership.dsapp' , 'a') as f:
			f.write("memberdn,groupdn\n")
			for i in xrange(len(member_and_group)):
				print (member_and_group[i])
				f.write(member_and_group[i] + '\n')

		if askYesOrNo("\nDoes the above appear correct"):
			copy_cmd = "copy \"membershipCache\" (memberdn,groupdn) from STDIN WITH DELIMITER ',' CSV HEADER"
			cur.execute("delete from \"membershipCache\"")
			logger.info('Removing old memberhipCache data')

			with open(glb.dsapptmp + '/ldapGroupMembership.dsapp' ,'r') as f:
				logger.info("Updating membershipCache with current data")
				cur.copy_expert(sql=copy_cmd, file=f)
				
			print ("\nGroup Membership has been updated\n")
			logger.info("Group membership has been updated")

			removed_disabled()
			print ()
			fix_referenceCount()

		cur.close()
		conn.close()
		
		os.remove (glb.dsapptmp + '/ldapGroupMembership.dsapp')
	else:
		print ("No results from LDAP")
		logger.warning("No results from LDAP")

def updateMobilityFTP():
	datasyncBanner()
	Config.read(glb.dsappSettings)
	dlPath = Config.get('Update URL', 'download.address')
	serviceCheck = Config.get('Update URL', 'check.service.address')
	serviceCheckPort = Config.getint('Update URL', 'check.service.port')

	if DoesServiceExist(serviceCheck, serviceCheckPort):
		print ("Mobility will restart during the upgrade")
		if askYesOrNo("Continue with update"):

			# Check if yast is opened
			if not checkYaST():
				return

			# Check URL connectivity
			ds = raw_input("Filename: ")
			if not ds:
				print ("\nNo input entered")
				return

			dbuild = ds.split('.')[0]
			os.chdir('/root/Downloads')
			if dlfile('%s%s' % (dlPath, ds)):

				# Get ISO name
				dsISO = file_content(ds)
				# Decompress file
				uncompressIt(ds)

				cmd = "zypper rr mobility"
				logger.debug(cmd)
				zypper = util_subprocess(cmd, True)

				cmd = "zypper addrepo 'iso:///?iso=%s&url=file:///root/Downloads' mobility" % dsISO[0]
				logger.debug(cmd)
				zypper = util_subprocess(cmd, True)

				dsUpdate('mobility')
	else:
		print ("Unable to connect to %s 21" % serviceCheck)

def updateMobilityISO():
	datasyncBanner()
	print ("Mobility will restart during the upgrade")
	if not askYesOrNo("Continue"):
		return

	# Check if yast is opened
	if not checkYaST():
		return

	# Get path / file
	print ()
	isoPath = getMobilityISO()
	if isoPath is None:
		print()
		return

	# Verify ISO is mobility iso
	if not checkISO_content(isoPath):
		return

	if askYesOrNo("\nUpdate with %s" % os.path.basename(isoPath)):

		# All checks paasses - Add isoPath as 'mobility' repo
		datasyncBanner()
		print ("Setting up mobility repository..")
		logger.info("Setting up mobility repository")
		cmd = "zypper rr mobility"
		logger.debug(cmd)
		zypper = util_subprocess(cmd, True)

		logger.info("Adding mobility repo")
		cmd = "zypper addrepo 'iso:///?iso=%s&url=file://%s' mobility" % (os.path.basename(isoPath), os.path.dirname(isoPath))
		logger.debug(cmd)
		zypper = util_subprocess(cmd, True)

		dsUpdate('mobility')

def getMobilityISO():
	isoPath = autoCompleteInput("Path to Mobility ISO directory or file: ")
	if os.path.isfile(isoPath):
		if not os.path.basename(isoPath).endswith('.iso'):
			print ("\nIncorrect extension type\nPlease select a ISO file")
			eContinue
			return None
	elif os.path.isdir(isoPath):
		# Create list of ISOs
		fileList = []
		for file in os.listdir(isoPath):
			if file.endswith('.iso'):
				fileList.append(file)

		# Build list and prompt
		if len(fileList) != 0:
			available = build_avaiable(fileList)
			choice = None
			datasyncBanner()

			# print list
			print ("     Detected ISOs")
			for x in range(len(fileList)):
				print ("     %s. %s" % (x, fileList[x]))
			print ("\n     q. Back")

			choice = get_choice(available)
			logger.debug("Selected choice: %s" % choice)
			if choice == None or choice == '':
				return None
			else:
				isoPath = isoPath + "/" + fileList[choice]
				logger.debug("ISO path: %s" % isoPath)

		else:
			print ("\nNo ISOs found at: %s" % isoPath)
			eContinue
			return None
	else:
		print ("No such directory or file: %s" % isoPath)
		logger.warning("No such directory or file: %s" % isoPath)
		return None
		
	return isoPath

def checkISO_content(isoPath):
	# Verify ISO is mobility iso
	cmd = "isoinfo -i '%s' -x \"/CONTENT.;1\"" % isoPath
	out = util_subprocess(cmd,True)

	output = StringIO.StringIO(out[0])
	isoContent = dict((i.split()[0].rstrip(' '),i.split()[1:]) for i in output.readlines())

	try:
		logger.debug("ISO Content:\n%s" % isoContent)
	except:
		logger.debug("ISO Conent is blank or didn't run")

	try:
		if 'Mobility' not in isoContent['LABEL'] and 'mobility' not in isoContent['LABEL']:
			datasyncBanner()
			print ("Not able to find mobility in ISO content")
			if not askYesOrNo("Continue with ISO (%s): " % os.path.basename(isoPath)):
				return False
	except:
		# No such key 'LABEL'
		datasyncBanner()
		print ("Unable to find content in ISO (%s)" % os.path.basename(isoPath))
		logger.error("Unable to find content in ISO (%s)" % os.path.basename(isoPath))
		if not askYesOrNo("Continue with ISO (%s): " % os.path.basename(isoPath)):
			return False

	logger.info("ISO (%s) selected" % os.path.basename(isoPath))
	return True

def checkNightlyMaintenance(healthCheck=False):
	setVariables()
	Config.read(glb.dsappSettings)
	previousLogs = Config.getint('Log', 'nightly.logs')

	nightlyMaint_results = dict()
	nightlyMaint_results['result'] = False

	if not healthCheck:
		datasyncBanner()
		
	nightlyMaint_results['output'] = "Scanning logs for maintenance..\n"
	logger.info("Scannning logs for maintenance..")
	time1 = time.time()

	# Open files, and get content to print later
	dbSetting = []
	logReport = []
	with open(glb.config_files['mconf'], 'r') as f:
		for line in f:
			if 'database' in line: dbSetting.append(line.strip())
	with open(glb.mAlog, 'r') as f:
		for line in f:
			if 'Nightly maintenance' in line: logReport.append(line.strip())
			fileName = os.path.basename(glb.mAlog)
	
	# If logReport is empty, check next 5 gziped logs
	if len(logReport) == 0:
		files = sorted(glob.glob(glb.log +'/connectors/mobility-agent.*'), key=os.path.getctime)
		try:
			files.remove(glb.log + '/connectors/mobility-agent.log')
		except:
			pass

		for file in files[-previousLogs:]:
			extension = os.path.splitext(file)[1]

			# Check if extension is gzip or bzip2
			if extension == '.gz':
				logger.debug("Opening %s with gzip" % file)
				with contextlib.closing(gzip.open('%s' % file, 'r')) as f:
					for line in f:
						if 'Nightly maintenance' in line: logReport.append(line.strip())
			elif extension == '.bz2':
				logger.debug("Opening %s with bzip2" % file)
				with contextlib.closing(bz2.BZ2File('%s' % file, 'r')) as f:
					for line in f:
						if 'Nightly maintenance' in line: logReport.append(line.strip())
			if len(logReport) != 0:
				fileName = file
				break

	time2 = time.time()
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

	nightlyMaint_results['output'] = nightlyMaint_results['output'] + "\nNightly Maintenance Settings:"
	for line in dbSetting:
		nightlyMaint_results['output'] = nightlyMaint_results['output'] + '\n' + line

	if glb.mobilityConfig['dbMaintenance'] != '1':
		nightlyMaint_results['result'] = True
		nightlyMaint_results['output'] = nightlyMaint_results['output'] + "\n\nNightly Maintenance disabled\n"
	elif glb.mobilityConfig['dbMaintenance'] == '1' and len(logReport) != 0:
		nightlyMaint_results['output'] = nightlyMaint_results['output'] + "\n\nNightly Maintenance History:\n"
		logger.info('Found maintenance history in: %s' % fileName)
		nightlyMaint_results['output'] = nightlyMaint_results['output'] + fileName
		for line in logReport[-5:]:
			nightlyMaint_results['output'] = nightlyMaint_results['output']  + '\n' + line
	else:
		nightlyMaint_results['output'] = nightlyMaint_results['output'] + "\n\nUnable to find nightly maintenance in past logs"
		logger.info("Unable to find nightly maintenance in past logs")
		nightlyMaint_results['result'] = True

	return nightlyMaint_results

def showStatus():
	# Pending sync items - Monitor
	data_found = False
	logger.info("Checking for pending events")
	conn = getConn('datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select state,count(*) from consumerevents where state!='1000' group by state")
	data = cur.fetchall()
	cur.close()
	conn.close()
	setVariables()
	if len(data) != 0:
		print ("GroupWise events:")
		for line in readlines_reverse(glb.gAlog):
			if 'queue' in line:
				print (line); break
		data_found = True
		logger.info("Found pending consumerevents")
		print (tabulate(data, headers="keys", tablefmt='orgtbl'))

	conn = getConn('mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select state,count(*) from syncevents where state!='1000' group by state")
	data = cur.fetchall()
	cur.close()
	conn.close()
	if len(data) != 0:
		print ("\nMobility events:")
		for line in readlines_reverse(glb.mAlog):
			if 'queue' in line:
				print (line); break
		data_found = True
		logger.info("Found pending syncevents")
		print (tabulate(data, headers="keys", tablefmt='orgtbl'))

	if not data_found:
		print ("No pending events")
		logger.info("No pending events")

def indexDB(database=None):
	pids = get_pid(glb.python_Directory)
	if len(pids) == 0:
		if database is None:
			cmd = "PGPASSWORD='%(pass)s' psql -U %(user)s datasync -c \"reindex database datasync\"" % glb.dbConfig
			logger.info("Indexing datasync database..")
			time1 = time.time()
			i = subprocess.Popen(cmd, shell=True)
			i.wait()
			time2 = time.time()
			logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

			cmd = "PGPASSWORD='%(pass)s' psql -U %(user)s mobility -c \"reindex database mobility\"" % glb.dbConfig
			logger.info("Indexing mobility database..")
			time1 = time.time()
			i = subprocess.Popen(cmd, shell=True)
			i.wait()
			time2 = time.time()
			logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

		elif database:
			cmd = "PGPASSWORD='%s' psql -U %s %s -c \"reindex database %s\"" % (glb.dbConfig['pass'], glb.dbConfig['user'], database, database)
			logger.info("Indexing mobility database..")
			time1 = time.time()
			i = subprocess.Popen(cmd, shell=True)
			i.wait()
			time2 = time.time()
			logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	else:
		print ("\nUnable to index databases. Mobility PID detected")
		logger.error("Unable to index databases. Mobility PID detected")

def vacuumDB(database=None):
	pids = get_pid(glb.python_Directory)
	if len(pids) == 0:
		if database is None:
			cmd = "PGPASSWORD='%(pass)s' vacuumdb -U %(user)s datasync --full -v" % glb.dbConfig
			logger.info("Vacuuming datasync database..")
			time1 = time.time()
			v = subprocess.Popen(cmd, shell=True)
			v.wait()
			time2 = time.time()
			logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

			cmd = "PGPASSWORD='%(pass)s' vacuumdb -U %(user)s mobility --full -v" % glb.dbConfig
			logger.info("Vacuuming mobility database..")
			time1 = time.time()
			v = subprocess.Popen(cmd, shell=True)
			v.wait()
			time2 = time.time()
			logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

		elif database:
			cmd = "PGPASSWORD='%s' vacuumdb -U %s %s --full -v" % (glb.dbConfig['pass'], glb.dbConfig['user'], database)
			logger.info("Vacuuming %s database.." % database)
			time1 = time.time()
			v = subprocess.Popen(cmd, shell=True)
			v.wait()
			time2 = time.time()
			logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	else:
		print ("\nUnable to vacuum databases. Mobility PID detected")
		logger.error("Unable to vacuum databases. Mobility PID detected")

def changeDBPass():
	datasyncBanner()
	if askYesOrNo("Change psql datasync_user password?"):
		p_input = getpass.getpass("Enter new password: ")
		if len(p_input) == 0:
			print ("Invalid input")
			sys.exit(1)

		vinput = getpass.getpass("Re-enter new password: ")
		if p_input != vinput:
			print ("\nPasswords do not match")
			sys.exit(1)

		print()

		# Get Encrypted password from user input
		inputEncrpt = encryptMSG(p_input)

		print ("Changing database password..")
		cmd = "su postgres -c \"cd /;psql -c \\\"ALTER USER datasync_user WITH password '%s';\\\"\"" % p_input
		logger.info("Changeing datasync_user database password")
		out = util_subprocess(cmd, True)
		if out[1]:
			print ("Failed changing database password")
			logger.error("Failed changing database password\n")
			return

		# Backup conf files
		backup_config_files(glb.config_files, 'changeDBPass')

		# Update XML files with new password
		if isProtected(glb.XMLconfig['ceconf'], './/configengine/database/protected'):
			setXML('.//configengine/database/password', glb.XMLconfig['ceconf'], inputEncrpt, glb.config_files['ceconf'])
		else:
			setXML('.//configengine/database/password', glb.XMLconfig['ceconf'], p_input, glb.config_files['ceconf'], hideValue=True)
		logger.info("Updated database password in %s" % glb.config_files['ceconf'])

		if isProtected(glb.XMLconfig['econf'], './/settings/database/protected'):
			setXML('.//settings/database/password', glb.XMLconfig['econf'], inputEncrpt, glb.config_files['econf'])
		else:
			setXML('.//settings/database/password', glb.XMLconfig['econf'], p_input, glb.config_files['econf'], hideValue=True)
		logger.info("Updated database password in %s" % glb.config_files['econf'])

		if isProtected(glb.XMLconfig['mconf'], './/settings/custom/protected'):
			setXML('.//settings/custom/dbpass', glb.XMLconfig['mconf'], inputEncrpt, glb.config_files['mconf'])
		else:
			setXML('.//settings/custom/dbpass', glb.XMLconfig['mconf'], p_input, glb.config_files['mconf'], hideValue=True)
		logger.info("Updated database password in %s" % glb.config_files['mconf'])

		print ("\nDatabase password updated. Please restart mobility\n")

def changeAppName():
	datasyncBanner()
	userConfig = verifyUser()[0]
	if userConfig['name'] is None:
		return

	if confirm_user(userConfig, 'datasync'):

		defaultMAppName = userConfig['mAppName']
		defaultGAppName = userConfig['gAppName']

		if defaultMAppName and defaultGAppName:

			mAppName = defaultMAppName
			gAppName = defaultGAppName
			print ()

			# Prompt user for new device app name and display default
			mAppName = raw_input("Enter user device application name [%s] " % mAppName)
			if not mAppName:
				mAppName = defaultMAppName

			# Prompt user for new groupwise app name and display default
			gAppName = raw_input("Enter user groupwise application name [%s] " % gAppName)
			if not gAppName:
				gAppName = defaultGAppName

			print ("\nDevice application name: %s" % mAppName)
			print ("Groupwise application name: %s " % gAppName)

			if askYesOrNo("Update %s application names" % userConfig['name']):
				logger.info("Updating %s application names" % userConfig['name'])
				
				conn = getConn('datasync')
				cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

				# pdates users application names with variable entries
				cmd = "UPDATE targets set \"targetName\"='%s' where dn='%s' AND \"connectorID\"='default.pipeline1.mobility'" % (mAppName, userConfig['dName'])
				cur.execute(cmd)
				logger.info("Set mobility application name to: %s" % mAppName)
				logger.debug("cmd: %s" % cmd)
				cmd = "UPDATE targets set \"targetName\"='%s' where dn='%s' AND \"connectorID\"='default.pipeline1.groupwise'" % (gAppName, userConfig['dName'])
				cur.execute(cmd)
				logger.info("Set groupwise application name to: %s" % gAppName)
				logger.debug("cmd: %s" % cmd)

				cur.close()
				conn.close()

				print ("\nRestart mobility to pick up changes.")
		else:
			print ("Unable to find application names")
			logger.warning("Unalbe to find all application names")

	print(); eContinue()

def reinitAllUsers(switch=False):
	if switch:
		conn = getConn('mobility')
		cur = conn.cursor()
		print ("Setting all users to reinitialize")
		logger.info("Setting all users to reinitialize")
		cur.execute("update users set state = '7'")
		cur.close()
		conn.close()
		print ("All users have been set to reinitialize")
		logger.info("All users have been set to reinitialize")
	else:
		datasyncBanner()
		print (textwrap.fill("Note: During the reinitialize, users will not be able to log in. This may take some time.", int(WINDOW_SIZE[1])))
		if askYesOrNo("Are you sure you want to reinitialize all the users"):
			conn = getConn('mobility')
			cur = conn.cursor()
			logger.info("Setting all users to reinitialize")
			cur.execute("update users set state = '7'")

			cur.close()
			conn.close()
			print ("\nAll users have been set to reinitialize")
			logger.info("All users have been set to reinitialize")

def reinitAllFailedUsers():
	datasyncBanner()
	if askYesOrNo("Reinitialize all failed users"):
		conn = getConn('mobility')
		cur = conn.cursor()
		logger.info("Setting all failed users to reinitialize")
		cur.execute("update users set state = '7' where state='5'")

		cur.close()
		conn.close()
		print ("\nAll failed users have been set to reinitialize")
		logger.info("All failed users have been set to reinitialize")



##################################################################################################
#	Start of Certificate
##################################################################################################

def certPath(prompt):
	certPath = autoCompleteInput(prompt)
	if promptVerifyPath(certPath):
		return certPath
	return ""

def pre_signCert():
	datasyncBanner()
	file_path = autoCompleteInput("Enter directory path for certificate files (ie. /root/certificates): ")
	file_path = file_path.rstrip('/')
	if os.path.isdir(file_path):
		if os.path.isdir(file_path):
			os.chdir(file_path)
			cmd = "ls --format=single-column | column"
			if askYesOrNo("List files"):
				subprocess.call(cmd, shell=True)
				print ()
		else:
			print ("No such directory: %s" % path)
			logger.warning("No such directory: %s" % path)
			return

		csr_path = autoCompleteInput("Certificate signing request (CSR): ")
		if not os.path.isfile(csr_path):
			print ("No such file: %s" % csr_path)
			logger.error("No such file: %s" % csr_path)
			return
		key_path = autoCompleteInput("Private key: ")
		if not os.path.isfile(key_path):
			print ("No such file: %s" % key_path)
			logger.error("No such file: %s" % key_path)
			return

		cn = getCommonName(csr_path)
		if cn is None:
			return
		signCert(path = file_path, csr = csr_path, key = key_path, commonName = cn)
	else:
		print ("No such directory: %s" % file_path)
		logger.warning("No such directory: %s" % file_path)
		return

def newCertPass():
	keyPass = getpass.getpass("Enter password for private key: ")
	confirmPass = getpass.getpass("Confirm password: ")
	if keyPass != confirmPass:
		print ("\nPasswords do not match")
		logger.warning("Passwords do not match")
		return None
	logger.info("Private key password created")
	return keyPass

def getCommonName(csrFile):
	cmd = "openssl req -in '%s' -text -noout" % csrFile
	out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
	out.wait()
	pout = p = out.communicate()[0]
	search = re.search('CN=.*', pout)
	if search is None:
		print ("\nFailed: Unable to get common name")
		logger.error("Failed: Unable to get common name")
		return None
	return search.group().split('=')[1].split('/')[0]

def signCert(path, csr, key, commonName, keyPass = None, sign = False):
	print ("\nSigning certificate")
	logger.info("Signing certificate..")
	if os.path.isfile(path + '/' + csr) and os.path.isfile(path + '/' + key):
		certDays = raw_input("Certificate Validity Period (Days): ")
		if certDays:
			certDays = '730'

		crt = "%s.crt" % commonName
		if keyPass is not None and keyPass:
			cmd = "openssl x509 -req -sha256 -days %s -in '%s/%s' -signkey '%s/%s' -out '%s/%s' -passin pass:%s &>/dev/null" % (certDays, path, csr, path, key, path, crt, keyPass)
		else:
			cmd = "openssl x509 -req -sha256 -days %s -in '%s/%s' -signkey '%s/%s' -out '%s/%s' &>/dev/null" % (certDays, path, csr, path, key, path, crt)
		logger.debug("Signing %s" % csr)
		signed = subprocess.call(cmd, shell=True)

		print ("Signed Server Certificate: %s/%s" % (path, crt))
		logger.info("Signed server certificate at %s" % path)
	else:
		print ("Unable to locate certificate files")

	if askYesOrNo("\nApply certificates (Generate PEM) now"):
		createPEM(True, commonName, keyPass, key, crt, path)

def createCSRKey(sign = False):
	datasyncBanner()
	#Start of Generate CSR and Key script.
	path = certPath("Enter path to store certificate files: ")
	if path:
		# Remove '/' from end of path
		path = path.rstrip('/')
		logger.debug("Certificate path: %s" % path)

		print ("\nGenerating a private key and certificate signing request (CSR)")
		logger.info("Generating a private key and CSR")
		keyPass = newCertPass()
		if keyPass is None:
			return
		print ()

		if keyPass:
			cmd = "openssl genrsa -passout pass:%s -des3 -out '%s/server.key' 2048" % (keyPass, path)
			logger.info("Creating private key..")
			key = subprocess.call(cmd, shell=True)
			cmd = "openssl req -sha256 -new -key '%s/server.key' -out '%s/server.csr' -passin pass:%s" % (path, path, keyPass)
			logger.info("Creating certificate signing request..")
			csr = subprocess.call(cmd, shell=True)
		else:
			cmd = "openssl genrsa -out '%s/server.key' 2048" % (path)
			logger.info("Creating private key..")
			key = subprocess.call(cmd, shell=True)
			cmd = "openssl req -sha256 -new -key '%s/server.key' -out '%s/server.csr'" % (path, path)
			logger.info("Creating certificate signing request..")
			csr = subprocess.call(cmd, shell=True)
		
		csr = '%s/server.csr' % path
		commonName = getCommonName(csr)
		if commonName is None:
			return
		print ("CommonName is : %s" % commonName)

		# Rename CSR and Key to common an used
		if os.path.isfile(path + '/%s.csr' % commonName):
			os.remove(path + '/%s.csr' % commonName)
		if os.path.isfile(path + '/%s.key' % commonName):
			os.remove(path + '/%s.key' % commonName)
		os.rename(path + '/server.csr', path + '/%s.csr' % commonName)
		os.rename(path + '/server.key', path + '/%s.key' % commonName)

		key = '%s.key' % commonName
		csr = '%s.csr' % commonName

		print ("\nPrivate Key: %s/%s" % (path, key))
		print ("Certificate Signing Request (CSR): %s/%s" % (path, csr))
		logger.info("Certificates created at %s" % path)

		if askYesOrNo("\nGenerate self signed-certificate from CSR"):
			signCert(path, csr, key, commonName, keyPass, sign)

def createPEM(sign = None, commonName = None, keyPass = None, key = None, crt = None, path = None):
	datasyncBanner()

	# Ask for files/path if not self-signed
	if not sign:
		# print (textwrap.fill("Please provide the private key, the public certificate, and any intermediate certificate or bundles.\n", int(WINDOW_SIZE[1])))
		path = autoCompleteInput("Enter directory path for certificate files (ie. /root/certificates): ")
		path = path.rstrip('/')
		if os.path.isdir(path):
			os.chdir(path)
			cmd = "ls --format=single-column | column"
			if askYesOrNo("List files"):
				subprocess.call(cmd, shell=True)
				print ()

			# Enter loops to get private key and public certificate
			logger.info("Getting private key..")
			while True:
				key = autoCompleteInput("Private key: ")
				if not os.path.isfile(key):
					print ("No such file: %s\n" % key)
					logger.warning("No such file: %s" % key)
					if not askYesOrNo("Try again"):
						return
				else:
					logger.info("Using private key: %s" % key)
					break
			logger.info("Getting public certificate..")
			while True:
				crt = autoCompleteInput("Public certificate: ")
				if not os.path.isfile(crt):
					print ("No such file: %s\n" % crt)
					logger.warning("No such file: %s" % crt)
					if not askYesOrNo("Try again"):
						return
				else:
					logger.info("Using public certificate: %s" % crt)
					break
		else:
			print ("No such directory: %s" % path)
			logger.warning("No such directory: %s" % path)
			return

	# Check if private key is passwordless
	cmd = "openssl rsa -in '%s/%s' -check -noout -passin pass:" % (path,key)
	chk = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	valid, error = chk.communicate()
	if error:
		# Check the private key password
		if keyPass is None:
			keyPass = getpass.getpass("Private key passphrase: ")
		cmd = "openssl rsa -in '%s/%s' -check -noout -passin pass:%s" % (path,key,keyPass)
		chk = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err = chk.communicate()
		if err:
			print ("Incorrect passphrase on %s/%s" % (path,key))
			logger.warning("Incorrect passphrase on %s" % key)
			return
		logger.info("Valid passphrase for private key %s" % key)
	else:
		logger.debug("Private key %s has no password" % key)
		keyPass=""

	# Check if public certifiate and private key match
	if not verifyCertifiateMatch(key, keyPass, crt, path):
		return

	# Get any intermediate certificates
	intermediateCAList = []
	if askYesOrNo("Any intermediate certificate files or bundles"):
		intermedFile = autoCompleteInput("Intermediate certificate: ")
		intermediateCAList.append(intermedFile)
		logger.debug("Adding intermediate file: %s" % intermedFile)
		while True:
			if askYesOrNo("Any additional intermediate certificate files or bundles"):
				intermedFile = autoCompleteInput("Intermediate certificate: ")
				intermediateCAList.append(intermedFile)
				logger.debug("Adding intermediate file: %s" % intermedFile)
			else:
				break

	# dos2unix all intermediate files
	for caFile in intermediateCAList:
		cmd = "dos2unix '%s/%s' &>/dev/null" % (path,caFile)
		tmp = subprocess.call(cmd, shell=True)

	# dos2unix the public certificate and private key
	cmd = "dos2unix '%s/%s' '%s/%s' &>/dev/null" % (path,key,path,crt)
	tmp = subprocess.call(cmd, shell=True)

	# Removing password from Private Key, if it contains one
	cmd = "openssl rsa -in '%s/%s' -out '%s/nopassword.key' -passin pass:%s &>/dev/null" % (path,key,path,keyPass)
	tmp = subprocess.call(cmd, shell=True)
	logger.debug("Creating %s/nopassword.key for mobility.pem" % path)

	# Remove any pervious mobility.pem files
	if os.path.isfile('%s/mobility.pem' % path):
		os.remove('%s/mobility.pem' % path)
		logger.debug("Removing previous %s/mobility.pem" % path)

	print ("\nCreating PEM..")
	# Create mobility.pem from public certificate, and private
	with open('%s/mobility.pem' % path, 'a') as openPem:
		with open('%s/nopassword.key' % path, 'r') as openKey:
			k = openKey.read().strip()
		with open('%s/%s' % (path,crt), 'r') as openCRT:
			cert = openCRT.read().strip()
		openPem.write(k + '\n')
		openPem.write(cert + '\n')

		# Add all intermediate files
		for caFile in intermediateCAList:
			with open('%s/%s' % (path,caFile), 'r') as openInter:
				interCert = openInter.read().strip()
			openPem.write(interCert + '\n')
	os.remove('%s/nopassword.key' % path)

	print ("PEM created at: %s/mobility.pem" % path)
	logger.info("PEM created at: %s/mobility.pem" % path)

	if askYesOrNo("\nInstall PEM"):
		logger.debug("Running certificate install..")
		configureMobilityCerts(path)

def configureMobilityCerts(path):
	certInstall = False
	datasyncBanner()

	if askYesOrNo("Implement pem certificate with Mobility devices"):
		shutil.copy(path + '/mobility.pem', glb.dirVarMobility + '/device/mobility.pem')
		print ("Copied mobility.pem to %s/device/mobility.pem" % glb.dirVarMobility)
		logger.info("Copied %s/mobility.pem to %s/device/mobility.pem" % (path, glb.dirVarMobility))
		certInstall = True

	if askYesOrNo("\nImplement pem certificate with Mobility web admin"):
		shutil.copy(path + '/mobility.pem', glb.dirVarMobility + '/webadmin/server.pem')
		print ("Copied mobility.pem to %s/webadmin/server.pem" % glb.dirVarMobility)
		logger.info("Copied %s/mobility.pem to %s/webadmin/server.pem" % (path, glb.dirVarMobility))
		certInstall = True

	if certInstall:
		if askYesOrNo("\nDo you want to restart Mobility services now"):
			rcDS('restart')
		else:
			print ("Note: Mobility services will need to be restarted for the PEM to become active")

def verifyCertifiateMatch(key = None, keyPass = None, crt = None, path = None):
	if key == None and crt == None and path == None:
		datasyncBanner()
		print ("Please provide the private key, the public certificate to verify match\n")
		path = autoCompleteInput("Enter directory path for certificate files (ie. /root/certificates): ")
		path = path.rstrip('/')
		if os.path.isdir(path):
			os.chdir(path)
			cmd = "ls --format=single-column | column"
			if askYesOrNo("List files"):
				subprocess.call(cmd, shell=True)
				print ()

			# Enter loops to get private key and public certificate
			logger.info("Getting private key..")
			while True:
				key = autoCompleteInput("Private key: ")
				if not os.path.isfile(key):
					print ("No such file: %s\n" % key)
					logger.warning("No such file: %s" % key)
					if not askYesOrNo("Try again"):
						return False
				else:
					logger.info("Using private key: %s" % key)
					break
			logger.info("Getting public certificate..")
			while True:
				crt = autoCompleteInput("Public certificate: ")
				if not os.path.isfile(crt):
					print ("No such file: %s\n" % crt)
					logger.warning("No such file: %s" % crt)
					if not askYesOrNo("Try again"):
						return False
				else:
					logger.info("Using public certificate: %s" % crt)
					break
		else:
			print ("No such directory: %s" % path)
			logger.warning("No such directory: %s" % path)
			return False

	# MD5 of public certificate
	cmd = "openssl x509 -noout -modulus -in '%s/%s' | openssl md5" % (path, crt)
	tmp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	crtMD5_good, crtMD5_err = tmp.communicate()
	if crtMD5_err:
		print ("Unable to load certificate")
		logger.warning("Unable to load certificate")
		return False

	# MD5 of private key
	if keyPass != None:
		cmd = "openssl rsa -noout -modulus -in '%s/%s' -passin pass:%s | openssl md5" % (path, key, keyPass)
	else:
		cmd = "openssl rsa -noout -modulus -in '%s/%s' | openssl md5" % (path, key)
	tmp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	keyMD5_good, keyMD5_err = tmp.communicate()
	if keyMD5_err:
		print ("Unable to load private key")
		logger.warning("Unable to load private key")
		return False

	if keyMD5_good == crtMD5_good:
		print ("\nValid: Public certificate and private key match")
		logger.info("Public certificate and private key match")
		return True
	else:
		print ("\nInvalid: Public certificate and private key mismatch")
		logger.warning("Public certificate and private key mismatch")
		return False

##################################################################################################
#	End of Certificate
##################################################################################################

def checkLDAP(ghc=False):
	if not (glb.ldapConfig['port'] or glb.ldapConfig['login'] or glb.ldapConfig['host'] or glb.ldapConfig['pass']) or (glb.ldapConfig['port'] == None or glb.ldapConfig['login'] == None or glb.ldapConfig['host'] == None or glb.ldapConfig['pass'] == None):
		if not ghc:
			print ("Unable to determine ldap variables")
		logger.warning("Unable to determine ldap variables")
		for key in glb.ldapConfig:
			if glb.ldapConfig[key] is None:
				logger.warning("glb.ldapConfig missing value in key: %s" % key)
		return False

	if glb.ldapConfig['secure'] == 'false':
		if 'o=' not in glb.ldapConfig['login']:
			cmd = "/usr/bin/ldapsearch -x -H ldap://%s:%s -D '%s' -w '%s' -l 5 -b '%s' cn" % (glb.ldapConfig['host'], glb.ldapConfig['port'], glb.ldapConfig['login'], glb.ldapConfig['pass'], glb.ldapConfig['group'][0])
		else:
			cmd = "/usr/bin/ldapsearch -x -H ldap://%(host)s:%(port)s -D '%(login)s' -w '%(pass)s' -l 5 '%(login)s' cn" % glb.ldapConfig
	elif glb.ldapConfig['secure'] == 'true':
		if 'o=' not in glb.ldapConfig['login']:
			cmd = "/usr/bin/ldapsearch -x -H ldaps://%s:%s -D '%s' -w '%s' -l 5 -b '%s' cn" % (glb.ldapConfig['host'], glb.ldapConfig['port'], glb.ldapConfig['login'], glb.ldapConfig['pass'], glb.ldapConfig['group'][0])
		else:
			cmd = "/usr/bin/ldapsearch -x -H ldaps://%(host)s:%(port)s -D '%(login)s' -w '%(pass)s' -l 5 '%(login)s' cn" % glb.ldapConfig
	else:
		try:
			logger.warning("glb.ldapConfig['secure'] = %s" % glb.ldapConfig['secure'])
		except:
			logger.warning("No 'secure' key in glb.ldapConfig")

		cmd = None

	if cmd is not None:
		# Create tempfile for large data
		name = tempfile.TemporaryFile(mode='w+b')

		logger.info("Testing LDAP connection")
		log_cmd = cmd.replace("-w '" + glb.ldapConfig['pass'] + "'","-w '*******'")
		logger.debug("LDAP test command: %s" % log_cmd)
		ldapCheck = subprocess.Popen(cmd, shell=True, stdout=name, stderr=subprocess.PIPE)
		ldapCheck.wait()
		name.seek(0)
		out = name.read()
		err = ldapCheck.communicate()[1]
	else:
		logger.warning("Unable to test LDAP connection")
		return False

	logger.debug("LDAP results out: %s" % out)
	logger.debug("LDAP results err: %s" % err)
	if out:
		logger.info("LDAP tested successfully")
		return True
	elif err:
		logger.warning("Unable to test LDAP connection")
		return False

def userLdapOrGw(userConfig, pro_type):
	result = None
	logger.info("Checking for %s provisioning for user: %s" % (pro_type, userConfig['name']))

	if pro_type == 'ldap':
		if 'cn=' in userConfig['dName']:
			logger.info("LDAP provioned user: %s" % userConfig['name'])
			result = True
		else:
			logger.warning("Failed to find LDAP provisioning for user: %s" % userConfig['name'])
			result = False

	if pro_type == 'groupwise':
		if 'cn=' not in userConfig['dName'] and userConfig['dName'] != None:
			logger.info("GroupWise provioned user: %s" % userConfig['name'])
			result = True
		else:
			logger.warning("Failed to find GroupWise Provisioning for user: %s" % userConfig['name'])
			result = False

	if  userConfig['dName'] == userConfig['mName']:
		logger.debug("Provisioning for user '%s' matches in both databases" % userConfig['name'])
	else:
		logger.warning("Provisioning or name for user '%s' does not match in both databases" % userConfig['name'])
		logger.debug("Datasync database: %s" % userConfig['dName'])
		logger.debug("Mobility database: %s" % userConfig['mName'])

	return result

def updateFDN():
	datasyncBanner()
	userConfig = verifyUser()[0]
	if userConfig['name'] is None:
		return

	if checkLDAP():
		if userConfig['verify'] != 0 and userConfig['verify'] is not None:
			if userLdapOrGw(userConfig, 'ldap'):
				multiple = False
				print ("Searching LDAP...")
				userDN = []

				if glb.ldapConfig['secure'] == 'false':
					cmd = "/usr/bin/ldapsearch -x -H ldap://%s:%s -D '%s' -w '%s' -l 5 -b '%s' -s base" % (glb.ldapConfig['host'], glb.ldapConfig['port'], glb.ldapConfig['login'], glb.ldapConfig['pass'], userConfig['dName'])
				elif glb.ldapConfig['secure'] == 'true':
					cmd = "/usr/bin/ldapsearch -x -H ldaps://%s:%s -D '%s' -w '%s' -l 5 -b '%s' -s base" % (glb.ldapConfig['host'], glb.ldapConfig['port'], glb.ldapConfig['login'], glb.ldapConfig['pass'], userConfig['dName'])
				logger.debug("LDAP cmd: %s" % cmd)
				tmp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				out, err = tmp.communicate()
				logger.debug("LDAP results out: %s" % out)
				logger.debug("LDAP results err: %s" % err)
				search = re.search('dn:.*', out)
				if search:
					userDN.append((' '.join(search.group().split(' ')[1:])))
				if len(userDN) != 0:
					print (list(set(userDN))[0])
				else:
					print ("Unable to find LDAP user '%(name)s' at: %(dName)s" % userConfig)
					logger.warning("Unable to find LDAP user '%(name)s' at: %(dName)s" % userConfig)
					if askYesOrNo("Expand search"):
						print ("\nSearching LDAP...")
						userDN = []
						for container in glb.ldapConfig['user']:
							if glb.ldapConfig['secure'] == 'false':
								cmd = "/usr/bin/ldapsearch -x -H ldap://%s:%s -D '%s' -w '%s' -l 5 -b '%s' 'cn=%s' -s base" % (glb.ldapConfig['host'], glb.ldapConfig['port'], glb.ldapConfig['login'], glb.ldapConfig['pass'], container, userConfig['name'])
							elif glb.ldapConfig['secure'] == 'true':
								cmd = "/usr/bin/ldapsearch -x -H ldaps://%s:%s -D '%s' -w '%s' -l 5 -b '%s' 'cn=%s' -s base" % (glb.ldapConfig['host'], glb.ldapConfig['port'], glb.ldapConfig['login'], glb.ldapConfig['pass'], container, userConfig['name'])
							logger.debug("LDAP cmd: %s" % cmd)
							tmp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
							out, err = tmp.communicate()
							logger.debug("LDAP results out: %s" % out)
							logger.debug("LDAP results err: %s" % err)
							search = re.findall('dn:.*', out)
							for dn in search:
								userDN.append((' '.join(search.group().split(' ')[1:])))
						userDN = list(set(userDN))

						if len(userDN) > 1:
							print ("Multiple user contexts found:")
							logger.info("Multiple user contexts found")
							for elem in userDN:
								print (elem)
							multiple = True
						elif len(userDN) == 1:
							print (list(set(userDN))[0])
						else:
							print ("Unable to find LDAP user '%(name)s' with: cn=%(name)s" % userConfig)
							logger.warning("Unable to find LDAP user '%(name)s' with: cn=%(name)s" % userConfig)
							return
					else:
						return

				# Prompt for new FDN
				if not multiple:
					defaultuserDN = userDN[0]
					print ("\nPress [Enter] to take LDAP defaults")
					userNewDN = raw_input ("Enter users new full FDN [%s]: " % defaultuserDN)
					if userNewDN == "":
						userNewDN = defaultuserDN
				else:
					userNewDN = raw_input("\nEnter users new full FDN: ")
					print (userNewDN)
					if not ('cn=' in userNewDN or 'CN=' in userNewDN) and not (',o=' in userNewDN or ',O=' in userNewDN):
						print ("Invalid FDN: %s" % userNewDN)
						logger.warning("Invalid FDN: %s" % userNewDN)
						return

				if userNewDN == userConfig['dName'] and userNewDN == userConfig['mName']:
					print ("\nUser FDN matches database [%s]. No changes made" % userConfig['dName'])
					logger.info("User FDN matches database [%s]. No changes made" % userConfig['dName'])
					if not askYesOrNo("Force update anyways"):
						return

				if askYesOrNo("\nUpdate [%s] to [%s]" % (userConfig['dName'], userNewDN)):
					logger.info("Updating '%s' to '%s'" % (userConfig['dName'], userNewDN))

					# Connect to datasync database to change FDN
					conn = getConn('datasync')
					cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
					cur.execute("update targets set dn='%s' where dn='%s' or dn='%s'" % (userNewDN, userConfig['dName'], userConfig['mName']))
					cur.execute("update cache set \"sourceDN\"='%s' where \"sourceDN\"='%s' or \"sourceDN\"='%s'" % (userNewDN, userConfig['dName'], userConfig['mName']))
					cur.execute("update \"folderMappings\" set \"targetDN\"='%s' where \"targetDN\"='%s' or \"targetDN\"='%s'" % (userNewDN, userConfig['dName'], userConfig['mName']))
					cur.execute("update \"membershipCache\" set memberdn='%s' where memberdn='%s' or memberdn='%s'" % (userNewDN, userConfig['dName'], userConfig['mName']))
					cur.close()
					conn.close()
					# Connect to mobility database to change FDN
					conn = getConn('mobility')
					cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
					cur.execute("update users set userid='%s' where userid='%s' or userid='%s'" % (userNewDN, userConfig['dName'], userConfig['mName']))
					cur.close()
					conn.close()

					print ("User FDN update complete\n\nRestart mobility for changes to take effect")
					logger.info("FND update complete")

			else:
				print ("Unable to get FDN. User '%s' is not LDAP provisioned" % userConfig['name'])
				logger.warning("Unable to get FDN. User '%s' is not LDAP provisioned" % userConfig['name'])
		else:
			if userConfig['verify'] is not None:
				print ("No such user '%s'" % userConfig['name'])
				logger.warning("User '%s' not found in databases" % userConfig['name'])
	print(); eContinue()

def getApplicationNames(userConfig):
	userConfig['mAppName'] = None
	userConfig['gAppName'] = None

	conn = getConn('datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

	cur.execute("select \"targetName\" from targets where (dn='%s' or dn ilike '%s.%%' or dn ilike 'cn=%s,%%') and \"connectorID\"='default.pipeline1.mobility' and disabled='0'" % (userConfig['dName'], userConfig['name'], userConfig['name']))
	data = cur.fetchall()
	for row in data:
		userConfig['mAppName'] = row['targetName']

	cur.execute("select \"targetName\" from targets where (dn='%s' or dn ilike '%s.%%' or dn ilike 'cn=%s,%%') and \"connectorID\"='default.pipeline1.groupwise' and disabled='0'" % (userConfig['dName'], userConfig['name'], userConfig['name']))
	data = cur.fetchall()
	for row in data:
		userConfig['gAppName'] = row['targetName']

	cur.close()
	conn.close()
	return userConfig

def build_avaiable(list):
	available = []
	for i in range(len(list)):
		available.append('%s' % i)
	return available

def printList(list, exitTxt = 'Back'):
	count = 0
	if len(list) != 0:
		for x in range(len(list)):
			print ("     %s. %s" % (count, list[x]))
			count += 1
		print ("\n     q. %s" % exitTxt)

def get_choice(available, special=None):
	if len(available) <= 9:
		print ("\n     Selection: ", end='')
	while True:
		if len(available) <= 9:
			choice = getch()
			if special is not None and choice == special:
				print()
				return special
			elif choice in available or choice == 'q' or choice == 'Q':
				if choice == 'q' or choice == 'Q':
					print()
					return
				else:
					print()
					return int(choice)
		else:
			choice = raw_input("\n     Selection: ")
			if choice == 'q' or choice == 'Q':
				print()
				return
			elif choice in available and choice.isdigit():
				print()
				return int(choice)
			else:
				datasyncBanner()
				print ("Invalid selection")
				return


##################################################################################################
#	Start of Patch / FTF Fixes
##################################################################################################

def getExactMobilityVersion():
	with open(glb.gmsVersion, 'r') as f:
		mVersion = f.read().translate(None, '.')
	return mVersion.rstrip()

def ftfPatchlevel(ftpFile, files):
	patchFile = glb.dsappConf + '/patch-file.conf'

	if not os.path.isfile(patchFile):
		open(patchFile, 'a').close()

	with open(patchFile, 'r') as openPatchFile:
		dsPatchLevel = openPatchFile.read()

	DATE = datetime.datetime.now().strftime("%X %F")
	if 'Applied fix %s to Mobility' % ftpFile not in dsPatchLevel:
		with open(patchFile, 'a') as f:
			f.write("Applied fix %s to Mobility version %s at %s:\n" % (ftpFile, getExactMobilityVersion(), DATE))
			for item in files:
				f.write(item + '\n')
			f.write('\n')

def ftfPatchlevelCheck(ftpFile, printList = True):
	patchFile = glb.dsappConf + '/patch-file.conf'
	if not os.path.isfile(patchFile):
		return True
	else:
		with open(patchFile, 'r') as f:
			patchFileContent = f.read()
		if printList:
			print (patchFileContent)
		if ftpFile in patchFileContent:
			datasyncBanner()
			print ("Patch %s has already been applied" % ftpFile)
			return False
		else:
			return True

def buildFTFPatchList(filePath):
	with open(filePath, 'r') as file:
		list = file.read().splitlines()

	patches = {}
	mobile_version = getExactMobilityVersion()

	patch_count = 0
	patch_item = 0
	patch_file = None
	patch_location = None
	patch_version = None
	patch_detail = None

	for item in list:
		if item is not '' and '#' not in item:
			if patch_item == 0:
				patch_file = item
			elif patch_item == 1:
				patch_version = item
			elif patch_item == 2:
				patch_detail = item
			elif patch_item == 3:
				patch_location = item.split(' ')

			patch_item += 1
			if patch_item == 4:
				if patch_version is not None and patch_version is not '' and mobile_version == patch_version:
					logger.debug("Adding file: %s to patch list" % patch_file)
					patches[patch_count] = {"file": patch_file, "version": patch_version, "detail": patch_detail, "location": patch_location}
					patch_count += 1
				patch_item = 0
		else:
			patch_item = 0
	return patches

def printFTFPatchList(patch_list):
	wrapper = textwrap.TextWrapper(subsequent_indent='        ', width=int(WINDOW_SIZE[1])-8)

	if len(patch_list) != 0:
		for x in range(len(patch_list)):
			print(wrapper.fill("     %s. %s" % (x, patch_list[x]['detail'])))
		print ("\n     q. Back")
	else:
		print ("No patches available")
		logger.info("No patches available")
		print(); eContinue()
		return False
	return True

def prepareFTF(patch_file):
	datasyncBanner()
	Config.read(glb.dsappSettings)
	serviceCheck = Config.get('FTF URL', 'check.service.address')
	serviceCheckPort = Config.getint('FTF URL', 'check.service.port')
	dlPath = Config.get('FTF URL', 'download.address')

	if DoesServiceExist(serviceCheck, serviceCheckPort):
		if dlfile('%s%s' % (dlPath, patch_file['file']), glb.dsapptmp):
			os.chdir(glb.dsapptmp)
			fileList = file_content(patch_file['file'])
			uncompressIt(patch_file['file'])

			# Validate fileList contains items in patch_file['location']
			for file in fileList:
				for path in patch_file['location']:
					if file not in path:
						print ("Patch file(s) do not match install path(s)")
						return

			return fileList
		return
	else:
		print ("Unable to connect to %s 21" % serviceCheck)
		return

def appyFTF(fileList, patch_file):
	date_fmt = datetime.datetime.now().strftime('%s')
	error = False
	os.chdir(glb.dsapptmp)
	print ()
	for files in patch_file['location']:
		file = os.path.basename(files)
		if file in fileList:
			# print (files)
			os.rename(files, files + '.bak_%s' % date_fmt)
			print ("Applying %s at %s" % (file, files))
			shutil.copy(file, files)
			logger.debug('Copying %s to %s' % (file, files))
		else:
			print ("Unable to apply %s" % files)
			logger.warning("Unable to apply: %s" % files)
			error = True

	if not error:
		print ("\nSuccessfully applied patch: %s" % patch_file['file'])
		print ("Restart Mobility for fixes")
		logger.info("\nSuccessfully applied patch: %s" % patch_file['file'])
		return True
	else:
		raw_input('wait')
		# Revert file(s) if failed applying fix
		print ("\nProblem applying files.\nReverting changes..")
		logger.info("Reverting changes..")
		for files in patch_file['location']:
			try:
				os.rename(files + '.bak_%s' % date_fmt, files)
				logger.debug("Attempting to rename %s back to %s" % (files + '.bak_%s' % date_fmt, files))
			except:
				pass
		return False

def selectFTFPatch(patch_list):
	available = build_avaiable(patch_list)
	choice = None
	if printFTFPatchList(patch_list):
		choice = get_choice(available)
	if choice == None or choice == '':
		return

	logger.debug("Selected patch option: %s" % choice)
	choice = int(choice)
	datasyncBanner()
	if askYesOrNo("Apply patch: %s\n%s" % (patch_list[choice]['file'], patch_list[choice]['detail'])):
		if ftfPatchlevelCheck(patch_list[choice]['file'], False):
			fileList = prepareFTF(patch_list[choice])
			if fileList is not None:
				if appyFTF(fileList, patch_list[choice]):
					ftfPatchlevel(patch_list[choice]['file'], patch_list[choice]['location'])
	print ();eContinue()

def showAppliedPatches():
	wrapper = textwrap.TextWrapper(subsequent_indent='             ', width=int(WINDOW_SIZE[1])-8)

	datasyncBanner()
	print ("Listing applied fixes..\n")
	logger.info("Listing applied fixes..")
	patchFile = glb.dsappConf + '/patch-file.conf'
	ftfList = glb.dsappConf + '/dsapp_FTFlist.txt'
	currentVersion = getExactMobilityVersion()
	printNext = False
	printNextFTF = False
	skipNext = False
	patchFound = False

	if os.path.isfile(patchFile):
		with open(patchFile, 'r') as f:
			for line in f:
				patch = None
				if currentVersion in line:
					print (line.strip().rstrip(':'))
					printNext = True
					patchFound = True

					# Find and print the description # DEV: Maybe use next() ?
					patch = (line.strip().split(' ')[2].strip())
					if os.path.isfile(ftfList) and patch is not None:
						with open(ftfList) as f2:
							for line2 in f2:
								if patch == line2.strip():
									skipNext = True
								elif skipNext:
									skipNext = False
									printNextFTF = True
								elif printNextFTF:
									printNextFTF = False
									print(wrapper.fill("Description: " + line2.strip()))
									logger.info("Applied FTF: %s" %line2.strip())
				elif printNext:
					print ("File(s): " + line)
					printNext = False
	if not patchFound:
		print ("No FTFs have been applied via dsapp\n")
		logger.info("No FTFs have been applied via dsapp")
	

##################################################################################################
#	End of Patch / FTF Fixes
##################################################################################################

def backupDatabase():
	datasyncBanner()
	DATE = datetime.datetime.now().strftime('%s')

	path = autoCompleteInput("Enter backup output path: ")
	if os.path.exists(path):
		print ("\nDumping databases..")
		logger.info("Dumping databases..")

		cmd = "PGPASSWORD='%s' pg_dump -U %s mobility > %s/mobility.BAK_%s.sql" % (glb.dbConfig['pass'], glb.dbConfig['user'], path, DATE)
		p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		p.wait()
		if not (p.communicate()[1]):
			print ("\nMobility database dump created : mobility.BAK_%s.sql " % DATE)
			logger.info("Mobility database dump created : mobility.BAK_%s.sql " % DATE)
		else:
			print ("\nError: Unable to dump mobility database")
			logger.warning("Unable to dump mobility database")

		cmd = "PGPASSWORD='%s' pg_dump -U %s datasync > %s/datasync.BAK_%s.sql" % (glb.dbConfig['pass'], glb.dbConfig['user'], path, DATE)
		p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		p.wait()
		if not (p.communicate()[1]):
			print ("Datasync database dump created : datasync.BAK_%s.sql " % DATE)
			logger.info("Datasync database dump created : datasync.BAK_%s.sql " % DATE)
		else:
			print ("Error: Unable to dump datasync database")
			logger.warning("Unable to dump datasync database")

	else:
		print ("Invalid path: %s" % path)
		logger.warning("Invalid path: %s" % path)


def restoreDatabase():
	# Local variables
	mobility_backup_count = 0
	datasync_backup_count = 0
	mobility_backup_list = []
	datasync_backup_list = []
	filesFound = False
	m_choice = 0
	d_choice = 0

	datasyncBanner()

	path = autoCompleteInput("Enter path to database backups: ")
	if not os.path.exists(path):
		print ("Invalid path")
		return

	# Check if any backup files are found
	files = os.listdir(path)
	for file in files:
		if 'datasync.BAK' in file or 'mobility.BAK' in file:
			if 'datasync.BAK' in file:
				datasync_backup_count += 1
				datasync_backup_list.append(file)
			if 'mobility.BAK' in file:
				mobility_backup_count += 1
				mobility_backup_list.append(file)
			filesFound = True
	if not filesFound:
		print ("No backups found in: %s" % path)
		logger.warning("No backups found in: %s" % path)
		return

	# If multiple Mobility DBs found
	if mobility_backup_count > 1:
		datasyncBanner()
		print ("Multiple mobility backups found\n")
		logger.debug("Multiple mobility backups found")
		available = build_avaiable(mobility_backup_list)
		printList(mobility_backup_list)
		m_choice = get_choice(available)
		if m_choice is None or m_choice is '': return


	# If multiple Datasync DBs found
	if datasync_backup_count > 1:
		datasyncBanner()
		print ("Multiple datasync backups found\n")
		logger.debug("Multiple datasync backups found")
		available = build_avaiable(datasync_backup_list)
		printList(datasync_backup_list)
		d_choice = get_choice(available)
		if d_choice is None or d_choice is '': return

	datasyncBanner()
	print ("Backups selected:")
	if mobility_backup_count != 0:
		print ("Mobility backup - %s" % mobility_backup_list[m_choice])
		logger.info("Mobility backup selected: %s" % mobility_backup_list[m_choice])
	if datasync_backup_count != 0:
		print ("Datasync backup - %s" % datasync_backup_list[d_choice])
		logger.info("Datasync backup selected: %s" % datasync_backup_list[d_choice])

	print ()
	if mobility_backup_count != 0:
		if askYesOrNo("Restore Mobility database"):
			# Dropping mobility database
			if dropSpecificDatabases('mobility'):
				createSpecificDatabases('mobility')
				cmd = "PGPASSWORD='%s' psql -U %s mobility < %s/%s" % (glb.dbConfig['pass'], glb.dbConfig['user'], path, mobility_backup_list[m_choice])
				print ("Restoring mobility: %s" % mobility_backup_list[m_choice])
				logger.info("Restoring mobility: %s" % mobility_backup_list[m_choice])
				p = subprocess.Popen(cmd,shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				p.wait()
				vacuumDB('mobility')
				indexDB('mobility')

	if datasync_backup_count != 0:
		if askYesOrNo("Restore Datasync database"):
			# Dropping datasync database
			if dropSpecificDatabases('datasync'):
				createSpecificDatabases('datasync')
				cmd = "PGPASSWORD='%s' psql -U %s datasync < %s/%s" % (glb.dbConfig['pass'], glb.dbConfig['user'], path, datasync_backup_list[d_choice])
				print ("Restoring mobility: %s" % mobility_backup_list[m_choice])
				logger.info("Restoring mobility: %s" % mobility_backup_list[m_choice])
				p = subprocess.Popen(cmd,shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				p.wait()
				vacuumDB('datasync')
				indexDB('datasync')

def getLogs():
	datasyncBanner()
	uploadVersion = glb.dsappupload + '/' + 'version'
	exceptionLog = glb.dsappLogs + '/exceptions.log'
	performanceLog = glb.dsappLogs + '/performance.log'

	if not askYesOrNo("Grab log files"):
		return

	sr_number = raw_input("SR#: ")
	compress_it = []
	removeAllFiles(glb.dsappupload)
	removeAllFolders(glb.dsappupload)
	os.makedirs(uploadVersion)
	print ("\nGrabbing log files..")
	logger.info("Grabbing log files..")

	# Get version information..
	print ("Grabbing version info..")
	logger.info("Grabbing version info..")
	
	with open(uploadVersion + '/mobility-version.txt', 'w') as file_write:
		with open(glb.gmsVersion, 'r') as file_read:
			file_write.write(file_read.read())
	compress_it.append('version/mobility-version.txt')

	with open(uploadVersion + '/os-version.txt', 'w') as file_write:
		for files in glob.glob(glb.serverinfo):
			with open(files, 'r') as file_read:
				file_write.write(file_read.read())
	compress_it.append('version/os-version.txt')

	print ("Grabbing rpm info..")
	with open(uploadVersion + '/rpm-info.txt', 'w') as file_write:
		rpmList = findRPM('*datasync*')
		for item in rpmList:
			file_write.write(item + '\n')
		rpmList = findRPM('*python*')
		for item in rpmList:
			file_write.write(item + '\n')
	compress_it.append('version/rpm-info.txt')

	# Grab XMLs
	print ("Grabbing XML..")
	for dirName, subdirList, fileList in os.walk(glb.dirEtcMobility):
		for fname in fileList:
			if '.xml' in fname:
				compress_it.append(dirName + '/' + fname)

	# Sync status
	print ("Checking sync status..")
	stdout = sys.stdout
	with open(glb.dsappupload + '/sync-status.txt', 'w') as sys.stdout:
		showStatus()
	sys.stdout = stdout
	compress_it.append('sync-status.txt')

	# Health Check
	if askYesOrNo("Run health check"):
		print ("Running health check..")
		ghc.generalHealthCheck(ghc_silent=True)
	compress_it.append(glb.ghcLog)

	# Compress log files
	DATE = datetime.datetime.now().strftime('%m-%d-%y_%H%M%S')
	os.chdir(glb.dsappupload)

	print ("\nCompressing logs for upload..")
	compress_it.append(glb.dsappLog)
	compress_it.append(glb.soapDebugLog)
	compress_it.append(exceptionLog)
	compress_it.append(performanceLog)
	compress_it.append(glb.sudslog)
	compress_it.append(glb.webadminlog)
	compress_it.append(glb.statuslog)
	compress_it.append(glb.configenginelog)
	compress_it.append(glb.connectormanagerlog)
	compress_it.append(glb.syncenginelog)
	compress_it.append(glb.monitorlog)
	compress_it.append(glb.systemagentlog)
	compress_it.append(glb.messagesLog)
	compress_it.append(glb.warnLog)
	compress_it.append(glb.updatelog)

	# Get variables from setting.cfg to number of logs to grab
	Config.read(glb.dsappSettings)
	mob_agent_Log = Config.getint('Upload Logs', 'mobility.agent')
	mob_log = Config.getint('Upload Logs', 'mobility')
	group_agent_log = Config.getint('Upload Logs', 'groupwise.agent')
	group_log = Config.getint('Upload Logs', 'groupwise')
	message_log = Config.getint('Upload Logs', 'messages')
	postgres_log = Config.getint('Upload Logs', 'postgres')

	# Get any folderStructure logs
	if os.path.exists(glb.dsappLogs + '/folderStructure'):
		files = sorted(glob.glob(glb.dsappLogs + '/folderStructure/*_folderStructure.log'))
		for file in files:
			compress_it.append(file)

	files = sorted(glob.glob(glb.log +'/connectors/mobility-agent.*'), key=os.path.getctime)
	for file in files[-mob_agent_Log:]:
		compress_it.append(file)
	files = sorted(glob.glob(glb.log +'/connectors/mobility.*'), key=os.path.getctime)
	for file in files[-mob_log:]:
		compress_it.append(file)
	files = sorted(glob.glob(glb.log +'/connectors/groupwise-agent.*'), key=os.path.getctime)
	for file in files[-group_agent_log:]:
		compress_it.append(file)
	files = sorted(glob.glob(glb.log +'/connectors/groupwise.*'), key=os.path.getctime)
	for file in files[-group_log:]:
		compress_it.append(file)

	# Compressed message logs
	files = sorted(glob.glob('/var/log/messages-*'), key=os.path.getctime)
	for file in files[-message_log:]:
		compress_it.append(file)

	# Postgres logs
	files = sorted(glob.glob('/var/lib/pgsql/data/pg_log/postgresql-*'), key=os.path.getctime)
	for file in files[-postgres_log:]:
		compress_it.append(file)

	# Tar up all files
	with contextlib.closing(tarfile.open("%s/%s_%s.tgz" % (glb.dsappupload, sr_number, DATE), "w:gz")) as tar:
		for path in compress_it:
			try:
			    tar.add(path)
			except OSError:
				logger.warning("No such file: %s" % path)

	if not os.path.isfile("%s/%s_%s.tgz" % (glb.dsappupload, sr_number, DATE)):
		print ("Error compressing files")
		logger.error("Could not compress files")
	else:
		# Clean up files
		shutil.rmtree(uploadVersion)
		os.remove(glb.dsappupload + '/sync-status.txt')

		Config.read(glb.dsappSettings)
		serviceCheck = Config.get('Upload URL', 'check.service.address')
		serviceCheckPort = Config.getint('Upload URL', 'check.service.port')
		upPath = Config.get('Upload URL', 'address')

		# FTP Send
		if askYesOrNo("Upload logs to %s" % glb.COMPANY_BU):
			if DoesServiceExist(serviceCheck, serviceCheckPort):
				print ("Connecting to ftp..\n")
				cmd = "curl -T %s/%s_%s.tgz %s" % (glb.dsappupload ,sr_number, DATE, upPath)
				out = subprocess.call(cmd,shell=True)

				print ("\nUploaded to %s: %s%s_%s.tgz" % (glb.COMPANY_BU, upPath, sr_number, DATE))
				logger.info("Uploaded to %s: %s%s_%s.tgz" % (glb.COMPANY_BU, upPath, sr_number, DATE))
			else:
				print ("Failed FTP: host (connection) might have problems\n")
				logger.warning("Failed FTP: host (connection) might have problems")

		print ("\nLogs at %s/%s_%s.tgz" % (glb.dsappupload ,sr_number, DATE))

def fix_gal():
	# Fix Global Address Book (GAL)
	datasyncBanner()
	if askYesOrNo("Do you want to remove the Global Address Book (GAL)"):
		conn = getConn('mobility')
		cur = conn.cursor()
		print ("Removing GAL..")
		cur.execute("delete from gal")
		cur.execute("delete from galsync")
		cur.close()
		conn.close()
		print ("\nNote: The Global Address Book (GAL) is recreated on startup")

def monitor_Sync_validate():
	datasyncBanner()
	userConfig = verifyUser()[0]
	if userConfig['name'] is None:
		return

	if userConfig['verify'] != 0:
		results_found = False
		print ("\nScanning log for sync validate..\n")
		logger.info(("Scanning log for sync validate.."))
		setVariables()
		with open(glb.mAlog, 'r') as open_file:
			for line in open_file:
				if '%s' % userConfig['name'] in line and 'Count' in line and 'MC' in line and 'Percentage' in line:
					results_found = True
					print (line)
		if not results_found:
			print ("No results found")
			logger.info("No results found")
	else:
		print ("No such user '%s'" % userConfig['name'])
		logger.warning("No such user '%s'" % userConfig['name'])

	print(); eContinue()

def removed_disabled():
	# datasyncBanner()
	if askYesOrNo("Remove all disabled users/groups from target table"):
		conn = getConn('datasync')
		cur = conn.cursor()
		print ("Cleaning up targets table..")
		logger.info("Cleaning up targets table..")
		cur.execute("delete from targets where disabled != '0'")
		cur.close()
		conn.close()

def fix_referenceCount():
	if askYesOrNo("Fix users/groups reference count"):
		conn = getConn('datasync')
		cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
		cur.execute("select \"referenceCount\",dn from targets where disabled != 1")
		target_data = cur.fetchall()
		cur.execute("select memberdn,groupdn from \"membershipCache\"")
		member_data = cur.fetchall()

		print ("Fixing users/groups reference count")
		for target_row in target_data:
			count = 0
			for member_row in member_data:
				if target_row['dn'] == member_row['memberdn']:
					count += 1
			if count == 0:
				cur.execute("update targets set \"referenceCount\"='1' where dn='%s'" % target_row['dn'])
				logger.debug("Updating %s referenceCount to 1" % target_row['dn'])
			else:
				cur.execute("update targets set \"referenceCount\"='%s' where dn='%s'" % (count, target_row['dn']))
				logger.debug("Updating %s referenceCount to %s" % (target_row['dn'], count))

		cur.close()
		conn.close()

def list_deviceInfo():
	datasyncBanner()
	cmd = "PGPASSWORD='%(pass)s' psql -U %(user)s mobility -c \"select u.userid, description, identifierstring, devicetype from devices d INNER JOIN users u ON d.userid = u.guid;\"" % glb.dbConfig
	logger.info("Listing all devices from the database")
	out = util_subprocess(cmd)
	pydoc.pager(out[0].rstrip('\n'))

def list_usersAndEmails():
	datasyncBanner()
	cmd = "PGPASSWORD='%(pass)s' psql -U %(user)s mobility -c \"select g.displayname, g.firstname, g.lastname, u.userid, g.emailaddress from gal g INNER JOIN users u ON (LOWER(g.alias) = LOWER(u.name));\"" % glb.dbConfig
	logger.info("Listing all users and emails")
	out = util_subprocess(cmd)
	pydoc.pager(out[0].rstrip('\n'))

def show_GW_syncEvents():
	datasyncBanner()
	conn = getConn('datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select count(*) from consumerevents")
	data = cur.fetchall()

	if (data[0]['count']) > 0:
		logger.info("Events found in consumerevents")
		cur.execute("select edata from consumerevents")
		data = cur.fetchall()
		userCount = dict()
		logger.debug("Sorting consumerevents by user..")
		for row in data:

			# Gets users sourceName
			if '<sourceName>' in row['edata']:
				userSouceDN = row['edata'].split('<sourceName>')[1].split('</sourceName>')[0]
				if userSouceDN in userCount:
					logger.debug("Updating key [%s]:[%s]" % (userSouceDN, userCount[userSouceDN] + 1))
					userCount[userSouceDN] += 1
				else:
					logger.debug("Found souce '%s'. Creating key" % userSouceDN)
					userCount[userSouceDN] = 1

			# Gets users sourceDN  if sourceName not found
			elif '<sourceDN>' in row['edata']: # Added sourceDN for GMS 14.2.0.
				userSouceDN = row['edata'].split('<sourceDN>')[1].split('</sourceDN>')[0]
				if userSouceDN in userCount:
					logger.debug("Updating key [%s]:[%s]" % (userSouceDN, userCount[userSouceDN] + 1))
					userCount[userSouceDN] += 1
				else:
					logger.debug("Found souce '%s'. Creating key" % userSouceDN)
					userCount[userSouceDN] = 1

			# List event as Unknown if neither sourceDN or sourceName are found
			else:
				userSouceDN = 'Unknown'
				if userSouceDN in userCount:
					logger.debug("Updating key [%s]:[%s]" % (userSouceDN, userCount[userSouceDN] + 1))
					userCount[userSouceDN] += 1
				else:
					logger.debug("Unable to find souce. Creating 'Unknown' key")
					userCount[userSouceDN] = 1

		logger.debug("Sorting keys on on values..")
		sorted_users = sorted(userCount.items(), key=operator.itemgetter(1),reverse=True)

		header = ['User', 'Events']
		printTable = "Note: Pending events may be valid\n\n"
		printTable += str(tabulate(sorted_users, header, tablefmt='orgtbl'))
		pydoc.pager(printTable)
	else:
		print ("consumerevents table has no events (psql:datasync)")
		logger.info("consumerevents table has no events (psql:datasync)")
		print(); eContinue()

	cur.close()
	conn.close()

def show_Mob_syncEvents():
	datasyncBanner()
	cmd = "PGPASSWORD='%(pass)s' psql -U %(user)s mobility -c \"select DISTINCT  u.userid AS \\\"FDN\\\", count(eventid) as \\\"Events\\\", se.userid FROM syncevents se INNER JOIN users u ON se.userid = u.guid GROUP BY u.userid, se.userid ORDER BY \\\"Events\\\" DESC;\"" % glb.dbConfig
	out = util_subprocess(cmd)
	logger.info("Checking mobility sync events")
	printTable = "Note: Pending events may be valid\n\n"
	printTable += str(out[0].rstrip('\n'))
	pydoc.pager(printTable)

def view_attach_byUser():
	datasyncBanner()
	cmd = "PGPASSWORD='%(pass)s' psql -U %(user)s mobility -c \"select u.name AS \\\"Name\\\", u.userid AS \\\"FDN\\\", ROUND(SUM(a.filesize)/1024/1024::numeric,4) AS \\\"MB\\\" from attachments a INNER JOIN attachmentmaps am ON a.attachmentid = am.attachmentid INNER JOIN users u ON am.userid = u.guid WHERE a.filestoreid != '0' GROUP BY u.name, u.userid ORDER BY \\\"MB\\\" DESC;\"" % glb.dbConfig
	out = util_subprocess(cmd)
	logger.info("Checking users attachments by MB")
	pydoc.pager(out[0].rstrip('\n'))

def view_users_attach():
	userConfig = verifyUser()[0]
	if userConfig['name'] is None:
		return

	if confirm_user(userConfig, 'mobility'):
		cmd = "PGPASSWORD='%s' psql -U %s mobility -c \"select a.filename AS \\\"File Name\\\", ROUND(a.filesize/1024/1024::numeric,4) AS \\\"MB\\\", a.tstamp AS \\\"Time Stamp\\\", a.filestoreid from attachments a INNER JOIN attachmentmaps am ON a.attachmentid = am.attachmentid INNER JOIN users u ON am.userid = u.guid WHERE u.userid='%s' GROUP BY a.filename, a.tstamp, a.filestoreid, a.filesize ORDER BY \\\"MB\\\" DESC;\"" % (glb.dbConfig['pass'], glb.dbConfig['user'], userConfig['mName'])
	out = util_subprocess(cmd)
	logger.info("Checking attachments on %s" % userConfig['name'])
	pydoc.pager(out[0].rstrip('\n'))

def check_mob_attachments():
	datasyncBanner()
	logger.info("Starting check on filestoreIDs..")
	time1 = time.time()
	conn = getConn('mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select filestoreid from attachments")
	data = cur.fetchall()
	cur.close()
	conn.close()

	database_files = []
	zeroRecords = 0
	dup_Count = 0
	orphaned_os_files = 0
	orphaned_db_files = 0

	for row in data:
		database_files.append(row['filestoreid'])
		if row['filestoreid'] == 0:
			zeroRecords += 1
	duplicatesRecords = dict((i, database_files.count(i)) for i in database_files)

	for key in duplicatesRecords:
		if duplicatesRecords[key] > 1:
			dup_Count += 1

	os_files = []
	for dirName, subdirList, fileList in os.walk(glb.dirVarMobility + '/mobility/attachments'):
		for fname in fileList:
			os_files.append(fname)

	unique_os_files = set(os_files)
	unique_db_files = set(database_files)
	orphaned_os_files = (len(set(unique_os_files).intersection(unique_db_files)) - len(unique_db_files))
	orphaned_db_files = (len(set(unique_db_files).intersection(unique_os_files)) - len(unique_os_files))

	print ("     %s filestoreid entires in the database" % len(database_files))
	print ("     %s filestoreid entires in the file system" % len(os_files))
	print ("\n     %s distinct filestoreid entires in the database" % len(unique_db_files))
	print ("     %s distinct filestoreid entires in the file system" % len(unique_os_files))
	print ("\n     %s duplicates filestoreid entires in the database" % dup_Count)
	print ("     %s 0-record filestoreid entires in the database" % zeroRecords)

	if orphaned_os_files > 0:
		print ("\n     Informational: %s orphans files on the file system" % orphaned_os_files)
	if orphaned_db_files > 0:
		print ("\n     Warning: %s entires missing from the file system!" % orphaned_db_files)

	time2 = time.time()
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

def check_userAuth():
	# User Authentication
	datasyncBanner()
	userConfig = verifyUser()[0]
	if userConfig['name'] is None:
		return

	# Confirm user exists in database
	if userConfig['verify'] == 0:
		print ("User '%s' not found" % userConfig['name'])
		logger.warning("User '%s' not found" % userConfig['name'])
		print(); eContinue()
		return

	setVariables()
	print ("\nCheck for User Authentication Problems:")
	print ("Checking log files..\n")
	logger.info("Checking log files for '%s'" % userConfig['mAppName'])
	error = False
	for line in readlines_reverse(glb.mAlog):

		# User locked/expired/disabled - "authentication problem"
		if userConfig['name'].lower() in line and 'description=User Database is temporarily disabled' in line:
			logger.debug("Line found: Account disabled")
			error = True
			errDate, errTime = line.split(' ')[0:2]
			authErrors = "%s had an authentication problem. %s %s\nThe user is locked, expired, and/or disabled\n" % (userConfig['name'].lower(), errDate, errTime)
			break

		# Incorrect Password - "Failed to Authenticate user <userID(FDN)>"
		if userConfig['name'].lower() in line and 'description=Invalid password' in line:
			logger.debug("Line found: Invalid password")
			error = True
			errDate, errTime = line.split(' ')[0:2]
			authErrors = "%s had a authentication problem %s %s\nThe password is incorrect\nSuggestion: See TID 7007504\n" % (userConfig['name'].lower(), errDate, errTime)
			break

		if userConfig['name'].lower() in line and 'description=LDAP authentication failed because the password has expired' in line:
			logger.debug("Line found: Password expired")
			error = True
			errDate, errTime = line.split(' ')[0:2]
			authErrors = "%s had a authentication problem %s %s\nThe password is expired\n" % (userConfig['name'].lower(), errDate, errTime)
			break

		# Database access has been denied - No password
		if userConfig['name'].lower() in line and 'description=User Database access has been denied' in line:
			logger.debug("Line found: User Database")
			error = True
			errDate, errTime = line.split(' ')[0:2]
			authErrors = "%s had a database problem %s %s\nUser may not have a password set for authentication type\n" % (userConfig['name'].lower(), errDate, errTime)
			break

		# Initial Sync Problem - "Connection Blocked - user <userID(FDN)> initial sync"
		if userConfig['name'].lower() in line and 'Connection Blocked' in line and 'has not completed the initial sync':
			logger.debug("Line found: Connection Blocked")
			error = True
			errDate, errTime = line.split(' ')[0:2]
			authErrors = "%s had a connection problem %s %s\nUser has not completed the initial sync\n" % (userConfig['name'].lower(), errDate, errTime)
			break

		if userConfig['name'].lower() in line and 'Connection Blocked' in line and 'sync failed':
			logger.debug("Line found: User failed")
			error = True
			errDate, errTime = line.split(' ')[0:2]
			authErrors = "%s had a sync problem %s %s\nUser initial sync failed\n" % (userConfig['name'].lower(), errDate, errTime)
		try:
			if userConfig['mAppName'] in line and 'Connection Blocked' in line and 'currently blocked from accessing the server':
				logger.debug("Line found: Quarantined")
				error = True
				errDate, errTime = line.split(' ')[0:2]
				authErrors = "%s had a connection problem %s %s\nDevice has been quarantined\n" % (userConfig['name'].lower(), errDate, errTime)
				break
		except:
			pass

		# TODO : Test LDAP communication
			# # Communication - "Can't contact LDAP server"
			# if (grep -i "$vuid" $glb.mAlog | grep -i "Can't contact LDAP server" > /dev/null); then
			# 	err=false
			# 	errDate=`grep -i "$vuid" $glb.mAlog | grep -i "Can't contact LDAP server" | cut -d" " -f1,2 | tail -1 | cut -d "." -f1`
			# 	ifReturn $"Mobility cannot contact LDAP server. $errDate\n Check LDAP settings in WebAdmin.\n"
			# fi

	if error:
		logger.info("Problems found with authentication for '%s'" % userConfig['name'].lower())
		logger.debug(authErrors)
		print (authErrors)
	if not error:
		logger.info("No problems detected")
		print ("No problems detected\n")

	eContinue()

def whereDidIComeFromAndWhereAmIGoingOrWhatHappenedToMe():
	datasyncBanner()
	displayName = raw_input("Item name (subject, folder, contact, calendar): ")
	if displayName:
		cmd = ("PGPASSWORD='%s' psql -U %s mobility -t -c \"drop table if exists tmp; select (xpath('./DisplayName/text()', di.edata::xml)) AS displayname,di.eclass,di.eaction,di.statedata,d.identifierstring,d.devicetype,d.description, d.deviceid, di.creationtime INTO tmp from deviceimages di INNER JOIN devices d ON (di.deviceid = d.deviceid) INNER JOIN users u ON di.userid = u.guid WHERE di.edata ilike '%%%s%%' ORDER BY di.creationtime ASC, di.eaction ASC; select * from tmp;\"" % (glb.dbConfig['pass'], glb.dbConfig['user'], displayName))
		out = util_subprocess(cmd,True)
		pydoc.pager(out[0])


def getUsers_and_Devices(showUsers=False, showDevices=False, showBoth=False):
	conn = getConn('mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	returns = dict()

	cur.execute("select count(*) from users")
	userCount = cur.fetchall()
	returns['userCount'] = userCount

	cur.execute("select count(*) from devices where devicetype!=''")
	deviceCount = cur.fetchall()
	returns['deviceCount'] = deviceCount

	cur.close()
	conn.close()

	if showBoth:
		cmd = "PGPASSWORD='%(pass)s' psql -U %(user)s mobility -c \"select u.userid, devicetype from devices d INNER JOIN users u ON d.userid = u.guid;\"" % glb.dbConfig
		returns['cmd'] = cmd

	if showUsers:
		cmd = "PGPASSWORD='%(pass)s' psql -U %(user)s mobility -c \"select userid from users;\"" % glb.dbConfig
		returns['cmd'] = cmd

	if showDevices:
		cmd = "PGPASSWORD='%(pass)s' psql -U %(user)s mobility -c \"select devicetype,description,tstamp from devices where devicetype!='' order by tstamp ASC;\"" % glb.dbConfig
		returns['cmd'] = cmd

	return returns

def getUserPAB():
	userConfig = verifyUser()[0]
	if userConfig['name'] is None:
		return

	if userConfig['type'] is None:
		print("Unable to find object type for '%s'" % userConfig['name'])
		logger.warning("Unable to find object type for '%s'" % userConfig['name'])
		eContinue()
		return

	conn = getConn('mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	logger.info("Getting PABs for '%s'.." % userConfig['name'])
	cur.execute("select di.edata from deviceimages di INNER JOIN users u ON di.userid = u.guid WHERE u.userid ilike 'cn=%(name)s,%%' OR u.userid ilike '%(name)s.%%'" % userConfig)
	data = cur.fetchall()
	cur.close()
	conn.close()

	objectType = userConfig['type']
	with open(glb.dsapptmp + '/userPab.txt', 'w') as pabFile:
		pabFile.write("%s '%s' PAB contacts in GAL\n" % (objectType.capitalize(), userConfig['name']))
		pabFile.write("\nAddress Book | Name | Email | Home Phone | Mobile Phone | Office Phone\n")
		pabFile.write("----------------------------------------------------------------------\n")
		for row in data:
			addressBook = ''
			firstname = ''
			lastname = ''
			middlename = ''
			emailAddress = ''
			mobileNumber = ''
			homeNumber = ''
			officeNumber = ''

			if 'ApplicationData' in row['edata'] and 'Contacts:' in row['edata']:
				try:
					firstname = row['edata'].split('A1:FirstName>')[1].split('</')[0]
				except:
					pass

				try:
					lastname = row['edata'].split('A1:LastName>')[1].split('</')[0]
				except:
					pass

				try:	
					middlename= row['edata'].split('A1:MiddleName>')[1].split('</')[0]
				except:
					pass

				try:
					emailAddress = row['edata'].split('A1:Email1Address>')[1].split('</')[0]
				except:
					pass

				try:
					mobileNumber = row['edata'].split('A1:MobileTelephoneNumber>')[1].split('</')[0]
				except:
					pass

				try:
					officeNumber = row['edata'].split('A1:BusinessTelephoneNumber>')[1].split('</')[0]
				except:
					pass

				try:
					homeNumber = row['edata'].split('A1:HomeTelephoneNumber>')[1].split('</')[0]
				except:
					pass

				try:
					addressBook = row['edata'].split('A1:Category>')[1].split('</')[0]
				except:
					pass

				pabFile.write("%s | %s %s %s | %s | %s | %s | %s\n" % (addressBook, firstname, middlename, lastname, emailAddress, homeNumber, mobileNumber, officeNumber))
	
	with open(glb.dsapptmp + '/userPab.txt', 'r') as pabFile:
		pydoc.pager(pabFile.read())

def clearTextEncryption():
	datasyncBanner()
	print ("This will remove all protected lines, and set passwords / key to clear text")
	if not askYesOrNo("Remove encryption from XMLs"):
		return

	# Backup XML files
	backup_config_files(glb.config_files, 'clear_text_xmls')

	print()
	if glb.ldapConfig['enabled'] == 'true':
		ldapPass = getpass.getpass("LDAP password: ")
	else:
		ldapPass = 'default'
	if glb.authConfig['smtpPassword'] is not None:
		smtpPass = getpass.getpass("SMTP Notification password: ")
	else:
		smtpPass = None

	dbPass = getpass.getpass("PSQL datasync_user password: ")
	trustedPass = autoCompleteInput("Trusted Application file or key: ")
	if os.path.isfile(trustedPass):
		with open(trustedPass, 'r') as trustFile:
			trustKey = trustFile.read().strip()
	else:
		trustKey = trustedPass.strip()

	print ("\nRemoving <protected> lines..")
	logger.info(("Removing <protected> lines.."))
	removeLine(glb.config_files['ceconf'], "<protected>")
	removeLine(glb.config_files['econf'], "<protected>")
	removeLine(glb.config_files['mconf'], "<protected>")
	removeLine(glb.config_files['gconf'], "<protected>")

	# Rebuilds XML trees
	logger.info('Rebuilding XML trees started')
	time1 = time.time()
	logger.debug('Rebuilding %s tree from: %s' % ('mconfXML', glb.config_files['mconf']))
	glb.XMLconfig['mconf'] = getXMLTree(glb.config_files['mconf'])
	logger.debug('Rebuilding %s tree from: %s' % ('econfXML', glb.config_files['econf']))
	glb.XMLconfig['econf'] = getXMLTree(glb.config_files['econf'])
	logger.debug('Rebuilding %s tree from: %s' % ('ceconfXML', glb.config_files['ceconf']))
	glb.XMLconfig['ceconf'] = getXMLTree(glb.config_files['ceconf'])
	logger.debug('Rebuilding %s tree from: %s' % ('gconfXML', glb.config_files['gconf']))
	glb.XMLconfig['gconf'] = getXMLTree(glb.config_files['gconf'])
	time2 = time.time()
	logger.info('Rebuilding XML trees complete')
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

	# Set all clear text passwords / key in XMLs
	print ("Updating XMLs with inputs..")
	logger.info("Updating XMLs with inputs..")

	setXML ('.//configengine/ldap/login/password', glb.XMLconfig['ceconf'], ldapPass, glb.config_files['ceconf'], hideValue=True)
	if smtpPass is not None:
		setXML ('.//configengine/notification/smtpPassword', glb.XMLconfig['ceconf'], smtpPass, glb.config_files['ceconf'], hideValue=True)
	setXML('.//settings/custom/trustedAppKey', glb.XMLconfig['gconf'], trustKey, glb.config_files['gconf'], hideValue=True)
	setXML('.//configengine/database/password', glb.XMLconfig['ceconf'], dbPass, glb.config_files['ceconf'], hideValue=True)
	setXML('.//settings/database/password', glb.XMLconfig['econf'], dbPass, glb.config_files['econf'], hideValue=True)
	setXML('.//settings/custom/dbpass', glb.XMLconfig['mconf'], dbPass, glb.config_files['mconf'], hideValue=True)

	print ("\nRun %s/update.sh to re-encrypt XMLs" % glb.dirOptMobility)

def getPostgresModDate():
	cmd = "su postgres -c \"cd /;psql -t -c \\\"SELECT (pg_stat_file('base/'||oid ||'/PG_VERSION')).modification FROM pg_database where datname='postgres';\\\"\""
	out = util_subprocess(cmd, True)

	return out[0].strip().split(' ')[0]

def getMobilityUserList():
	userList = []
	conn = getConn('mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	logger.debug("Getting list of all mobility users")
	cur.execute("SELECT name from users")
	data = cur.fetchall()
	cur.close()
	conn.close()

	for row in data:
		userList.append(row['name'])
	return userList

def removeDevice(userConfig = None):
	lastGUIDS = []
	parser = etree.XMLParser(remove_blank_text=True)

	conn = getConn('mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

	# Remove device for specific user
	if userConfig is not None:
		print ("\nRemoving all devices for %s.." % userConfig['name'])
		logger.info("Removing all devices for %s" % userConfig['name'])
		cur.execute("SELECT guid FROM users WHERE userid='%s'" % userConfig['mName'])
		guids = cur.fetchall()

	# Remove device for all users
	else:
		print ("\nRemoving all devices for all users..")
		logger.info("Removing all devices for all users")
		# Get a list of all users GUID
		cur.execute("SELECT guid FROM users")
		guids = cur.fetchall()

	# Loop through guid list
	for guid in guids:
		# Get devices
		cur.execute("SELECT deviceid FROM devices WHERE userid='%s'" % guid['guid'])
		devices = cur.fetchall()
		if len(devices) <= 1:
			lastGUIDS.append(devices[0]['deviceid'])
		else:
			lastGUIDS.append(devices.pop()['deviceid'])

			deleteGUIDS = []
			for device in devices:
				deleteGUIDS.append(device['deviceid'])

			if len(deleteGUIDS) >= 1:
				logger.info("Removing guids: %s" % deleteGUIDS)

				cur.execute("DELETE FROM foldermaps WHERE deviceid = ANY(%s)", (deleteGUIDS,))
				logger.debug("Query: %s" % cur.query)
				logger.debug("Results: %s" % cur.statusmessage)

				cur.execute("DELETE FROM syncevents WHERE deviceid = ANY(%s)", (deleteGUIDS,))
				logger.debug("Query: %s" % cur.query)
				logger.debug("Results: %s" % cur.statusmessage)

				cur.execute("DELETE FROM deviceevents WHERE deviceid = ANY(%s)", (deleteGUIDS,))
				logger.debug("Query: %s" % cur.query)
				logger.debug("Results: %s" % cur.statusmessage)

				cur.execute("DELETE FROM deviceimages WHERE deviceid = ANY(%s)", (deleteGUIDS,))
				logger.debug("Query: %s" % cur.query)
				logger.debug("Results: %s" % cur.statusmessage)

				cur.execute("DELETE FROM devices WHERE deviceid = ANY(%s)", (deleteGUIDS,))
				logger.debug("Query: %s" % cur.query)
				logger.debug("Results: %s" % cur.statusmessage)

	# Set last devices blank
	for guid in lastGUIDS:
		logger.info("Setting default blank value to guid: %s" % guid)

		cur.execute("UPDATE devices SET identifierstring='', description='', state='0', statedata='{}' WHERE deviceid='%s'" % guid)
		logger.debug("Query: %s" % cur.query)
		logger.debug("Results: %s" % cur.statusmessage)

		cur.execute("UPDATE deviceimages SET synckey='0' WHERE deviceid='%s' AND state<>'1000'" % guid)
		logger.debug("Query: %s" % cur.query)
		logger.debug("Results: %s" % cur.statusmessage)

		cur.execute("UPDATE foldermaps SET synckey='1' WHERE deviceid='%s'" % guid)
		logger.debug("Query: %s" % cur.query)
		logger.debug("Results: %s" % cur.statusmessage)

		cur.execute("UPDATE foldermaps SET synckey='0' WHERE deviceid='%s' AND folderid='0'" % guid)
		logger.debug("Query: %s" % cur.query)
		logger.debug("Results: %s" % cur.statusmessage)

		cur.execute("DELETE FROM deviceevents WHERE deviceid='%s'" % guid)
		logger.debug("Query: %s" % cur.query)
		logger.debug("Results: %s" % cur.statusmessage)

		cur.execute("DELETE FROM syncevents WHERE deviceid='%s'" % guid)
		logger.debug("Query: %s" % cur.query)
		logger.debug("Results: %s" % cur.statusmessage)

		cur.execute("SELECT deviceconfig FROM devices WHERE deviceid='%s'" % guid)
		logger.debug("Query: %s" % cur.query)
		logger.debug("Results: %s" % cur.statusmessage)

		deviceconfig = cur.fetchall()

		if len(deviceconfig) > 0:
			tree = etree.fromstring(deviceconfig[0]['deviceconfig'], parser)
			path = tree.find('aggregateContacts')
			if path is not None:
				tree.remove(path)
				logger.debug("Found XML path: %s" % path)
			path = tree.find('aggregateCalendars')
			if path is not None:
				tree.remove(path)
				logger.debug("Found XML path: %s" % path)

			cur.execute("UPDATE devices SET deviceconfig='%s' WHERE deviceid='%s'" % (etree.tostring(tree, pretty_print=False), guid))
			logger.debug("Query: %s" % cur.query)
			logger.debug("Results: %s" % cur.statusmessage)


	cur.close()
	conn.close()

	print ("Removal complete\n")
	eContinue()