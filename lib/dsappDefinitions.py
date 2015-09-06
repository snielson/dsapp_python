from __future__ import print_function
import os
import sys
import signal
import getpass
import shutil
import fileinput
import glob
import atexit
import time
import itertools
import subprocess
import socket
import re
import rpm
import contextlib
import tarfile, zipfile
from urllib2 import urlopen, URLError, HTTPError
import xml.etree.ElementTree as ET
from xml.parsers.expat import ExpatError
import logging
import logging.config

sys.path.append('./lib')
import spin

# Log Settings
logging.config.fileConfig('/opt/novell/datasync/tools/dsapp/conf/logging.cfg')
logger = logging.getLogger(__name__)

def set_spinner():
	spinner = spin.progress_bar_loading()
	spinner.setDaemon(True)
	return spinner

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
	try:
		for fLine in fileinput.input(filePath, inplace=True):
			if line in fLine:
				continue
			print(fLine, end='')
	except OSError:
		logger.warning('No such file or directory: ' + filePath)

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
			print ("Mobility is not installed")
			logger.info('Mobility is not installed')
			sys.exit(1)
		return True

def getVersion(isInstalled,version):
	if isInstalled:
		try:
			with open(version) as f:
				return f.read()
		except IOError:
			print ("Unable to find: ", version)
			logger.error('Unable to find: ' + version)
			sys.exit(1)

def findReplace(find, replace, filePath):
	for line in fileinput.input(filePath, inplace=True):
		print(line.replace(find,replace), end='')

def pushConf(attribute, value, filePath):
	# TODO : May not be needed with ConfigParser
	find = str(attribute + "=.*")
	replace = str(attribute + "=" + value)

	logger.debug('Updating: ' + attribute + ' to: ' + value)
	for line in fileinput.input(filePath, inplace=True):
		print(re.sub(find, replace, line), end='')

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

def getXMLTree(filePath):
	try:
		return ET.ElementTree(file=filePath)
		logger.debug(filePath + " loaded as XML tree")
	except IOError:
		print ('\ndsapp has encountered an error. See log for more details')
		logger.error('Unable to find file: ' + filePath)
		sys.exit(1)
	except ExpatError:
		print ('\ndsapp has encountered an error. See log for more details')
		logger.error('Unable to parse XML: %s' % (filePath))
		sys.exit(1)

def xmlpath (elem, tree):
	# Example of elem: './/configengine/ldap/enabled/'
	try:
		return (tree.find(elem).text)
	except AttributeError:
		logger.exception('Got an exception error:')
		sys.exit(1)

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
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
        	logger.debug('%s: %s' % (question, valid[default]))
        	return valid[default]
        elif choice in valid:
        	logger.debug('%s: %s' % (question, valid[choice]))
        	return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

def unzip_file(fileName):
	with contextlib.closing(zipfile.ZipFile(fileName, 'r')) as z:
	    z.extractall()

def untar_file(fileName):
	with contextlib.closing(tarfile.open(fileName, 'r:gz')) as tar:
		tar.extractall()

def uncompressIt(fileName):
	extension = os.path.splitext(fileName)[1]
	options = {'.tar': untar_file,'.zip': unzip_file, '.tgz': untar_file}
	options[extension](fileName)


def DoesServiceExist(host, port):
    captive_dns_addr = ""
    host_addr = ""

    try:
        captive_dns_addr = socket.gethostbyname("thisURLdoesntexist.com")
    except:
        pass

    try:
        host_addr = socket.gethostbyname(host)

        if (captive_dns_addr == host_addr):
        	logger.info('Failed to test to %s:%s' %(host,port))
        	return False

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        s.close()
    except:
    	logger.info('Failed to test to %s:%s' %(host,port))
    	return False

    logger.info('Successfully tested to %s:%s' %(host,port))
    return True

def dlfile(url,print_url=True):
    # Open the url
    spinner = set_spinner()
    try:
        f = urlopen(url)
        if print_url:
	        print ("Downloading %s " % (url), end='')
	        logger.info('Downloading %s' % (url))
	        spinner.start(); time.sleep(.000001)
        # Open our local file for writing
        with open(os.path.basename(url), "wb") as local_file:
            local_file.write(f.read())

    #handle errors
    except HTTPError, e:
    	logger.warning("HTTP Error: %s %s" %(e.reason, url))
    	return False
    except URLError, e:
    	logger.warning("URL Error: %s %s" %(e.reason, url))
    	return False
    else:
    	return True
    finally:
    	if print_url:
	    	spinner.stop(); print()


#################### RPM definitions ###################
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
	for h in mi:
		list.append("%s-%s-%s" % (h['name'], h['version'], h['release']))
	return list

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
	    	print ("This will update:")
	    	log = 'Updating'
	    elif flag == 'i':
	    	print ("This will install:")
	    	log = 'Installing'
	    for te in ts:
	        print ("%s-%s-%s" % (te.N(), te.V(), te.R()))
	        logger.info("%s %s-%s-%s started" % (log, te.N(), te.V(), te.R()))

		if flag == 'u':
		    print ("\nUpdating... ", end='')
		if flag == 'i':
			print ("\nInstalling... ", end='')

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