# Written by Shane Nielson <snielson@projectuminfinitas.com>

from __future__ import print_function
import os,base64,binascii,sys,signal,select,getpass,shutil,fileinput,glob,atexit,time,datetime,itertools,pprint,textwrap
import subprocess,socket,re,rpm,contextlib
import tarfile, zipfile
import thread, threading
from pipes import quote
import io
import gzip
import urllib2
import readline
from urllib2 import urlopen, URLError, HTTPError
from lxml import etree
from xml.parsers.expat import ExpatError
import logging, logging.config
from multiprocessing import Process
import ConfigParser
Config = ConfigParser.ConfigParser()

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import spin
import filestoreIdToPath
import psycopg2
import psycopg2.extras
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import getch
getch = getch._Getch()


# Global variables
forceMode = False
installedConnector = "/etc/init.d/datasync-connectors"
isInstalled = False
problem = False

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

# Misc variables
serverinfo = "/etc/*release"
rpminfo = "datasync"
dsapp_tar = "dsapp.tgz"
isNum = '^[0-9]+$'
ds_20x= 2000
ds_21x = 2100
previousVersion = 20153
latestVersion = 210230
rcScript = None
mobilityVersion = 0
version = "/opt/novell/datasync/version"

# Mobility Directories
dirOptMobility = "/opt/novell/datasync"
dirEtcMobility = "/etc/datasync"
dirVarMobility = "/var/lib/datasync"
log = "/var/log/datasync"
dirPGSQL = "/var/lib/pgsql"
mAttach = dirVarMobility + "/mobility/attachments/"

# Mobility logs
configenginelog = log + "/configengine/configengine.log"
connectormanagerlog = log + "/syncengine/connectorManager.log"
syncenginelog = log + "/syncengine/engine.log"
monitorlog = log + "/monitorengine/monitor.log"
systemagentlog = log + "/monitorengine/systemagent.log"
updatelog = log + "/update.log"
webadminlog = log + "/webadmin/server.log"
mAlog = None
gAlog = None
mlog = None
glog = None

# System logs
messages = "/var/log/messages"
warn = "/var/log/warn"

# dsapp Conf / Logs
dsappSettings = dsappConf + "/setting.cfg"
dsappLogSettings = dsappConf + "/logging.cfg"
dsappLog = dsappConf + "/dsapp.log"
ghcLog = dsappConf + "/generalHealthCheck.log"

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (dsappConf))
logger = logging.getLogger(__name__)

# Define Variables for Eenou+ (2.x)
def declareVariables2():
	global rcScript
	global mAlog
	global gAlog
	global mlog
	global glog

	logger.debug('Setting version variables for 2.X')
	mAlog = log + "/connectors/mobility-agent.log"
	gAlog = log + "/connectors/groupwise-agent.log"
	mlog = log + "/connectors/mobility.log"
	glog = log + "/connectors/groupwise.log"
	rcScript = "rcgms"

# Define Variables for Pre-Eenou (1.x)
def declareVariables1():
	global rcScript
	global mAlog
	global gAlog
	global mlog
	global glog

	logger.debug('Setting version variables for 1.X')
	mAlog = log + "/connectors/default.pipeline1.mobility-AppInterface.log"
	gAlog = log + "/connectors/default.pipeline1.groupwise-AppInterface.log"
	mlog = log + "/connectors/default.pipeline1.mobility.log"
	glog = log + "/connectors/default.pipeline1.groupwise.log"
	rcScript="rcdatasync"

def set_dsappversion(version):
	global dsappversion
	dsappversion = version

def set_forcemode(force):
	global forceMode
	forceMode = force

def set_spinner():
	spinner = spin.progress_bar_loading()
	spinner.setDaemon(True)
	return spinner

def print_disclaimer(dsappversion):
	datasyncBanner(dsappversion)
	prompt = 'Use at your own discretion. dsapp is not supported by Novell.\nSee [dsapp --bug] to report issues.'
	print (prompt)
	r,w,x = select.select([sys.stdin], [], [], 10)
	sys.stdout.flush()

def clear():
	tmp = subprocess.call('clear',shell=True)

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

def announceNewFeature():
	Config.read(dsappSettings)
	newFeature = Config.getboolean('Settings', 'new.feature')

	if newFeature:
		datasyncBanner(dsappversion)
		logger.debug('Prompt feature')
		print ("General Health Check.\nLocated in the Checks & Queries menu.\n")
		if askYesOrNo("Would you like to run it now?"):
			pass
			# TODO: generalHealthCheck()
	Config.read(dsappSettings)
	Config.set('Settings', 'new.feature', False)
	with open(dsappSettings, 'wb') as cfgfile:
		Config.write(cfgfile)

def check_pid(pid):        
  try:
    os.kill(pid, 0)
  except OSError:
    return False
  else:
    return True

def get_pid(name):
	return os.popen('pgrep -f %s' % (name)).read().split()

def kill_pid(pid, sig=1):
	try:
		os.kill(pid, sig)
		logger.info('Killing process: %s' %(pid))
	except OSError:
		logger.warning('No such process: %s' %(pid))

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
		try:
			os.remove(f)
		except OSError:
			logger.warning('No such file or directory: %s' % (f))
		logger.debug('Removed: %s' % f)

def removeAllFolders(path):
	folderlist = glob.glob(path + "/*")
	for f in folderlist:
		try:
			shutil.rmtree(f)
		except OSError:
			logger.warning('No such directory: %s' % f)
		logger.debug('Removed: %s' % f)

def eContinue():
	print("Press Enter to continue ", end='')
	while True:
		enter = getch()
		if ord(enter) == 13:
			break
	print()

def break_loop():
	return True

def eContinueTime(timeout=5):
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

def getXMLTree(filePath):
	try:
		return etree.parse(filePath)
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
		logger.warning('Unable to find %s' % (elem))

def xmlpath_findall(elem, tree): # TODO : Fix to find all children with same tag
	xml_list = []
	try:
		for node in tree.findall(elem):
			xml_list.append(node.text)
		return (xml_list)
	except AttributeError:
		logger.warning('Unable to find %s' % (elem))

def setXML (elem, tree, value, filePath):
	root = tree.getroot()
	path = root.xpath(elem)
	if value is not None:
		path[0].text = value
		try:
			etree.ElementTree(root).write(filePath, pretty_print=True)
			logger.debug("Set '%s' at %s in %s" % (value, elem, filePath))
		except:
			logger.warning('Unable to set %s at %s in %s' % (value, elem, filePath))


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

def zip_content(fileName):
	with contextlib.closing(zipfile.ZipFile(fileName, 'r')) as z:
		return z.namelist()

def tar_content(fileName):
	with contextlib.closing(tarfile.open(fileName, 'r:gz')) as tar:
		return tar.getnames()

def file_content(fileName):
	extension = os.path.splitext(fileName)[1]
	options = {'.tar': tar_content,'.zip': zip_content, '.tgz': tar_content}
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

def dlfile(url,path=None, print_url=True):
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
		print ("No such file or directory %s" % url)
		logger.warning("URL Error: %s %s" %(e.reason, url))
		return False
	else:
		return True
	finally:
		if print_url:
			spinner.stop(); print()

def updateDsapp(publicVersion):
	print ('Updating dsapp to v%s' % (publicVersion))
	logger.info('Updating dsapp to v%s' % (publicVersion))

	# Download new version & extract
	dlfile('ftp://ftp.novell.com/outgoing/%s' % (dsapp_tar))
	print ()
	tar = tarfile.open(dsapp_tar, 'r:gz')
	rpmFile = re.search('.*.rpm' ,'%s' % (tar.getnames()[0])).group(0)
	tar.close()
	uncompressIt(dsapp_tar)
	check_rpm = checkRPM(rpmFile)
	if check_rpm:
		setupRPM(rpmFile)
	elif check_rpm == None:
		setupRPM(rpmFile, 'i')
	else:
		print ('%s is older than installed version' % (rpmFile))
		logger.warning('%s is older than installed version' % (rpmFile))

	# Clean up files
	try:
		os.remove('dsapp.sh')
	except OSError:
		logger.warning('No such file: dsapp.sh')
	try:
		os.remove(rpmFile)
	except OSError:
		logger.warning('No such file: %s' % (rpmFile))
	try:
		os.remove(dsapp_tar)
	except OSError:
		logger.warning('No such file: %s' % (dsapp_tar))
	# TODO: Close script, and relaunch

def autoUpdateDsapp():
	# Assign variables based on settings.cfg
	Config.read(dsappSettings)
	autoUpdate = Config.getboolean('Settings', 'auto.update')

	# Variable declared above autoUpdate=true
	if autoUpdate:
		# Check FTP connectivity
		if DoesServiceExist('ftp.novell.com', 21):
			# Fetch online dsapp and store to memory, check version
			spinner = set_spinner()
			logger.info('Checking for a newer version of dsapp')
			print ('Checking for a newer version of dsapp... ', end='')
			spinner.start(); time.sleep(.000001)
			for line in urllib2.urlopen('ftp://ftp.novell.com/outgoing/dsapp-version.info'):
				publicVersion = line.split("'")[1]
			spinner.stop(); print ()
			clear()
			
			# Download if newer version is available
			if dsappversion < publicVersion and publicVersion is not None:
				print ('v%s (v%s available)' % (dsappversion, publicVersion))
				logger.info('Updating dsapp v%s to v%s' % (dsappversion, publicVersion))
				updateDsapp(publicVersion)
			elif dsappversion >= publicVersion and publicVersion is not None:
				logger.info('dsapp is up-to-date at v%s' % dsappversion)

def getDSVersion():
	if checkInstall(forceMode, installedConnector):
		with open(version) as f:
			value = f.read().translate(None, '.')[0:4]
		return value

def setVariables():
	dsVersion = getDSVersion()
	# Depends on version 1.x or 2.x
	if checkInstall(forceMode, installedConnector):
		if dsVersion > ds_20x:
			declareVariables2()
		else:
			declareVariables1()

def dsUpdate(repo):
	spinner = set_spinner()
	if '%s/common/lib' % dirOptMobility not in sys.path:
		sys.path.append(dirOptMobility + '/common/lib/')
	import upgrade

	ref = subprocess.Popen(['zypper', 'ref', '-f', repo], stdout=subprocess.PIPE)
	ref.wait()
	zLU = subprocess.Popen(['zypper', 'lu', '-r', repo], stdout=subprocess.PIPE).communicate()
	if 'No updates found' in zLU[0]:
		print ("\nMobility is already this version, or newer")
		logger.info('Unable to update mobility. Same version or newer')
		if askYesOrNo('List %s packages' % repo):
			pkg = subprocess.Popen(['zypper', 'pa', '-ir', '%s' % repo])
			pkg.wait()
			logger.info('Listing %s packages' % repo)
			print ()
			if askYesOrNo("Force install %s packages" % repo):
				print ("Force updating Mobility.. ", end='')
				logger.info('Force updating Mobility..')
				spinner.start(); time.sleep(.000001)
				time1 = time.time()
				install = subprocess.Popen(['zypper', '--non-interactive', 'install', '--force', '%s:' % repo], stdout=subprocess.PIPE)
				install.wait()
				spinner.stop(); print ()
				time2 = time.time()
				logger.info("Foce update Mobility package complete")
				logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
				print ("\nPlease run 'sh %s/update.sh' to complete the upgrade" % dirOptMobility)
	else:
		print ("Updating Mobility.. ", end='')
		logger.info('Updating Mobility started')
		spinner.start(); time.sleep(.000001)
		time1 = time.time()
		install = subprocess.Popen(['zypper', '--non-interactive', 'update', '--force', '-r', '%s' % repo], stdout=subprocess.PIPE)
		install.wait()
		spinner.stop(); print ()
		time2 = time.time()
		logger.info("Updating Mobility package complete")
		logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

		# Update config file
		dsVersion = getDSVersion()
		Config.read(dsappSettings)
		Config.set('Misc', 'mobility.version', dsVersion)
		with open(dsappSettings, 'wb') as cfgfile:
			Config.write(cfgfile)
		# setVariables()

		logger.info('Updating Mobility schema started')
		time1 = time.time()
		rcDS('stop')
		os.environ["FEEDBACK"] = ""
		os.environ["LOGGER"] = ""

		pre = upgrade.Pre_Update()
		if pre.get_it_done():
			update = upgrade.connectorUpgrade(pre.version)
			update.install_monitor()
			update.service_upgrade()
		time2 = time.time()
		logger.info("Updating Mobility schema complete")
		logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

		p = subprocess.Popen(['rcpostgresql', 'stop'], stdout=subprocess.PIPE)
		p.wait()
		pids = get_pid('/usr/bin/python')
		for pid in pids:
			kill_pid(int(pid), 9)
		
		# Update config file
		dsVersion = getDSVersion()
		Config.read(dsappSettings)
		Config.set('Misc', 'mobility.version', dsVersion)
		with open(dsappSettings, 'wb') as cfgfile:
			Config.write(cfgfile)
		# setVariables()

		# getExactMobilityVersion
		p = subprocess.Popen(['rcpostgresql', 'start'], stdout=subprocess.PIPE)
		p.wait()
		rcDS('start')

		with open(dirOptMobility + '/version') as v:
			version = v.read()
		print ("\nYour Mobility product has been successfully updated to %s" % version)
		logger.info('Mobility product successfully updated to %s' % version)


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
		spinner.start(); time.sleep(.000001)

		ts.run(runCallback, 1)
		spinner.stop(); print ()

		print ("Uninstall complete\n")
		logger.info("%s %s-%s-%s complete" % (log, te.N(), te.V(), te.R()))
	else:
		print ("Error: Unresolved dependencies, transaction failed.")
		print (unresolved_dependencies)

#################### End of RPM definitions ###################

def protect(msg, encode, path, host = None, key = None):
# Code from GroupWise Mobility Service (GMS) datasync.util.
# Modified for dsapp
	result = None
	if host is None:
		if encode:
			result = base64.urlsafe_b64encode(os.popen('echo -n %s | openssl enc -aes-256-cbc -a -k `hostname -f`' % quote(msg)).read().rstrip())
		else:
			msg = base64.urlsafe_b64decode(msg)
			result = os.popen('echo %s | openssl enc -d -aes-256-cbc -a -k `hostname -f` 2>%s/decode_error_check' % (quote(msg),dsapptmp)).read().rstrip()
	else:
		if encode:
			result = base64.urlsafe_b64encode(os.popen('echo -n %s | openssl enc -aes-256-cbc -a -k %s' % (quote(msg),host)).read().rstrip())
		else:
			msg = base64.urlsafe_b64decode(msg)
			result = os.popen('echo %s | openssl enc -d -aes-256-cbc -a -k %s 2>%s/decode_error_check' % (quote(msg),host,dsapptmp)).read().rstrip()

	# Check for errors
	if os.path.isfile(dsapptmp + '/decode_error_check') and os.stat(dsapptmp + '/decode_error_check').st_size != 0 and path is not None:
		logger.error('bad decrypt - error decoding %s' % (path))
		os.remove(dsapptmp + '/decode_error_check')

		# TODO: Prompt user to attempt to fix files
		print ('\ndsapp has encountered an error. See log for more details')
		sys.exit(1)
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

def getDecrypted(check_path, tree, pro_path, host = None):
	try:
		protected = xmlpath(pro_path, tree)
	except:
		pass

	if protected is None:
		return xmlpath(check_path, tree)
	elif int(protected) == 1:
		return protect(xmlpath(check_path, tree), 0, check_path, host)
	elif int(protected) == 0:
		return xmlpath(check_path,tree)

def isProtected(tree, pro_path):
	protected = xmlpath(pro_path, tree)
	if protected is None:
		return False
	elif int(protected) == 1:
		return True
	elif int(protected) == 0:
		return False


def createPGPASS(config):
	# TODO: May no longer be needed with psycopg2, or other methods to access the database
	pgpass = '/root/.pgpass'
	#Creating new .pgpass file
	logger.debug('Creating new ~/.pgpass file')
	with open(pgpass, 'w') as f:
		f.write("*:*:*:*:%s" % (config['pass']))
	os.chmod(pgpass, 0600)

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
				backup_file(list[path],'%s/%s' % (dsappBackup,fname))
			else:
				backup_file(list[path],'%s' % (dsappBackup))

def check_hostname(old_host, XMLconfig, config_files):
	new_host = os.popen('echo `hostname -f`').read().rstrip()
	if old_host != new_host:
		print ("Hostname %s does not match configured %s" % (new_host, old_host))
		logger.warning('Hostname %s does not match %s' % (new_host,old_host))
		if askYesOrNo('Attempt to reconfigure XMLs:'):
			update_xml_encrypt(XMLconfig, config_files, old_host, new_host)
			Config.read(dsappSettings)
			Config.set('Misc', 'hostname', new_host)
			with open(dsappSettings, 'wb') as cfgfile:
				Config.write(cfgfile)

def find_old_hostname():
	pass # TODO: Write the code to match old dsapp, or simply prompt for old hostname?

def update_xml_encrypt(XMLconfig, config_files, old_host, new_host):
	# Attempt to get all encrypted in clear text using old_host
	before = {}
	before['smtp'] = getDecrypted('.//configengine/notification/smtpPassword', XMLconfig['ceconf'], './/configengine/notification/protected', old_host)
	before['ldap'] = getDecrypted('.//configengine/ldap/login/password', XMLconfig['ceconf'], './/configengine/ldap/login/protected', old_host)
	before['key'] = getDecrypted('.//settings/custom/trustedAppKey', XMLconfig['gconf'], './/settings/custom/protected', old_host)
	before['ceconf_db'] = getDecrypted('.//configengine/database/password', XMLconfig['ceconf'], './/configengine/database/protected', old_host)
	before['mconf_db'] = getDecrypted('.//settings/custom/dbpass', XMLconfig['mconf'], './/settings/custom/protected', old_host)
	before['econf_db'] = getDecrypted('.//settings/database/password', XMLconfig['econf'], './/settings/database/protected', old_host)
	
	after = {}
	after['smtp'] = getEncrypted(before['smtp'], XMLconfig['ceconf'], './/configengine/notification/protected', new_host)
	after['ldap'] = getEncrypted(before['ldap'], XMLconfig['ceconf'], './/configengine/ldap/login/protected', new_host)
	after['key'] = getEncrypted(before['key'], XMLconfig['gconf'], './/settings/custom/protected', new_host)
	after['ceconf_db'] = getEncrypted(before['ceconf_db'], XMLconfig['ceconf'], './/configengine/database/protected', new_host)
	after['mconf_db'] = getEncrypted(before['mconf_db'], XMLconfig['mconf'], './/settings/custom/protected', new_host)
	after['econf_db'] = getEncrypted(before['econf_db'], XMLconfig['econf'], './/settings/database/protected', new_host)
	
	# Backup XML files
	backup_config_files(config_files, 'update_xml_encrypt')

	# Update the XMLs
	setXML('.//configengine/notification/smtpPassword', XMLconfig['ceconf'], after['smtp'], config_files['ceconf'])
	setXML('.//configengine/ldap/login/password', XMLconfig['ceconf'], after['ldap'], config_files['ceconf'])
	setXML('.//settings/custom/trustedAppKey', XMLconfig['gconf'], after['key'], config_files['gconf'])
	setXML('.//configengine/database/password', XMLconfig['ceconf'], after['ceconf_db'], config_files['ceconf'])
	setXML('.//settings/database/password', XMLconfig['econf'], after['econf_db'], config_files['econf'])
	setXML('.//settings/custom/dbpass', XMLconfig['mconf'], after['mconf_db'], config_files['mconf'])

def promptVerifyPath(path):
	if not os.path.exists(path):
		if askYesOrNo("Path does not exist, would you like to create it now"):
			logger.info('Creating folder: %s' % (path))
			os.makedirs(path)
		else:
			return False
	return True
	
def checkYaST():
	# Check if YaST is running
	yast_runnning = get_pid('yast')
	for pid in yast_runnning:
		pid = int(pid)
		if check_pid(pid):
			print ('YaST is running. Close YaST before proceeding')
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
							return False
					else:
						return False
			else:
				return False
	return True

#### Postgres Definitions #####

def checkPostgresql(dbConfig):
	try:
		conn = psycopg2.connect("dbname='postgres' user='%s' host='%s' password='%s'" % (dbConfig['user'],dbConfig['host'],dbConfig['pass']))
		logger.info('Successfully connected to postgresql [user=%s,pass=%s]' % (dbConfig['user'],"*" * len(dbConfig['pass'])))
		conn.close()
	except:
		print ('\ndsapp has encountered an error. See log for more details')
		logger.error('Unable to connect to postgresql [user=%s,pass=%s]' % (dbConfig['user'],"*" * len(dbConfig['pass'])))
		return False
	return True

def getConn(dbConfig, database):
	# Assume connection is valid, as checkPostgresql is tested on startup
	try:
		conn = psycopg2.connect("dbname='%s' user='%s' host='%s' password='%s'" % (database, dbConfig['user'],dbConfig['host'],dbConfig['pass']))
	except:
		return None
	conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
	return conn

def dumpTable(dbConfig, database, tableName, targetSave):
	filePath = "%s/%s.sql" %(targetSave, tableName)
	if os.path.isfile(filePath):
		print ("%s already exists.\nCreated : %s" % (filePath, time.ctime(os.path.getctime(filePath))))
		logger.info("%s already exists. Created : %s" % (filePath, time.ctime(os.path.getctime(filePath))))
		print ()
		if not askYesOrNo("Overwrite SQL dump"):
			return
	logger.info("Dumping %s table from %s database to %s" % (tableName, database, filePath))
	cmd = "PGPASSWORD=%s pg_dump -U %s %s -D -a -t '\"%s\"' > %s" % (dbConfig['pass'], dbConfig['user'], database, tableName, filePath)
	dump = subprocess.call(cmd, shell=True)

def dropDatabases(dbConfig):
	conn = getConn(dbConfig, 'postgres')
	cur = conn.cursor()

	Config.read(dsappSettings)
	mobile_version = Config.get('Misc', 'mobility.version')
	mobile_version = int(mobile_version)

	#Dropping Tables
	print ("Dropping datasync database")
	logger.info("Dropping databases started")
	time1 = time.time()
	try:
		cur.execute("DROP DATABASE datasync")
		logger.info('Dropped datasync database')
	except:
		print('Unable to drop datasync database')
		logger.error('Unable to drop datasync database')
		cur.close()
		conn.close()
		return

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

	if mobile_version > ds_20x:
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

def verify_clean_database(dbConfig):
	check = [('datasync',), ('mobility',), ('dsmonitor',)]
	conn = getConn(dbConfig, 'postgres')
	cur = conn.cursor()
	cur.execute("SELECT datname from pg_database")
	databases = cur.fetchall()

	for d in databases:
		if d in check:
			return False
	return True

def createDatabases(dbConfig):
	conn = getConn(dbConfig, 'postgres')
	cur = conn.cursor()

	Config.read(dsappSettings)
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
	if mobile_version > ds_20x:
		cur.execute("CREATE DATABASE dsmonitor")
		print("DSmonitor database done")
		logger.info('dsmonitor database created')
	cur.close()
	conn.close()

	# Opening connection with datasync database
	print('\nExtending schema..')
	logger.info('Extending schema in databases')
	conn = getConn(dbConfig, 'datasync')
	cur = conn.cursor()
	cur.execute(open(dirOptMobility + '/common/sql/postgresql/configengine.sql', 'r').read())
	cur.execute(open(dirOptMobility + '/common/sql/postgresql/datasync.sql', 'r').read())
	print('Extending schema on datasync done')
	logger.info('Extending schema on datasync complete')

	DATE = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	with open(version, 'r') as f:
		VERSION = f.read()
	command = {'DATE': DATE, 'VERSION': VERSION}
	INSERT = "INSERT INTO services (service, initial_version, initial_timestamp, previous_version, previous_timestamp, service_version, service_timestamp) VALUES ('Mobility','', '%(DATE)s', '%(VERSION)s', '%(DATE)s', '%(VERSION)s', '%(DATE)s');" % command
	cur.execute(INSERT)
	print("Added service record")
	logger.info('Added service record to datasync')
	cur.close()
	conn.close()

	# Opening connection with mobility database
	conn = getConn(dbConfig, 'mobility')
	cur = conn.cursor()
	cur.execute(open(dirOptMobility + '/syncengine/connectors/mobility/mobility_pgsql.sql', 'r').read())
	print('Extending schema on mobility done')
	logger.info('Extending schema on mobility complete')
	cur.close()
	conn.close()

	if mobile_version > ds_20x:
		conn = getConn(dbConfig, 'dsmonitor')
		cur = conn.cursor()
		cur.execute(open(dirOptMobility + '/monitorengine/sql/monitor.sql', 'r').read())
		print('Extending schema on dsmonitor done')
		logger.info('Extending schema on dsmonitor complete')
		cur.close()
		conn.close()
	time2 = time.time()
	print('\nDatabase creation done')
	logger.info('Creating databases complete')
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

###### End of Postgresql Definitions ########

def cuso(dbConfig, op = 'everything'):
	print ('Running CUSO..\n')
	logger.info('Starting CUSO')
	time1 = time.time()
	continue_cleanup = False
	if op == 'user':
		dumpTable(dbConfig, 'datasync', 'membershipCache', dsappdata)
		dumpTable(dbConfig, 'datasync', 'targets', dsappdata)

	# Dropping Tables
	dropDatabases(dbConfig)

	# Check if database is clean
	if verify_clean_database(dbConfig):
		# Recreate tables switch
		if op != 'uninstall':
			# Recreating Databases
			createDatabases(dbConfig)
			if op == 'user':
				# Repopulating targets and membershipCache
				conn = getConn(dbConfig, 'datasync')
				cur = conn.cursor()
				cur.execute(open(dsappdata +'/targets.sql').read())
				logger.info('Imported targets.sql into datasync database')
				cur.execute(open(dsappdata +'/membershipCache.sql').read())
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
			if dsappversion > 194:
				removeRPM('dsapp')

			# Copy logs to /tmp before removing /opt/novell/datasync/
			if os.path.isfile(dsappLogs) and os.path.exists('/tmp/'):
				logger.info('Copying %s to /tmp/' % (dsappLogs))
				shutil.copy(dsappLogs, '/tmp/')

			folders = [dirPGSQL, dirEtcMobility, dirVarMobility, log, dirOptMobility]
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

	if continue_cleanup:
		# Remove attachments.
		spinner = set_spinner()
		print('Cleaning up attachments ', end='')
		spinner.start(); time.sleep(.000001)
		removeAllFolders(dirVarMobility + '/syncengine/attachments')
		removeAllFolders(dirVarMobility + '/mobility/attachments')
		spinner.stop(); print()

	time2 = time.time()
	print('CUSO complete')
	logger.info('CUSO complete')
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

def registerDS():
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
		    print(textwrap.fill("\nThe code or email address you provided appear to be invalid or there is trouble contacting registration servers.").lstrip())
		    logger.warning('Failed to register mobility')
		else:
			print("\nYour Mobility product has been successfully activated.")
			logger.info('Mobility successfully registered')
			logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

	eContinue()

def cleanLog():
	print("Cleaning logs..")
	removeAllFiles(log + '/connectors')
	removeAllFiles(log + '/syncengine')
	if askYesOrNo("To prevent future disk space hogging, set log maxage to 14"):
		logger.info('Setting max log days to 14')
		os.popen("sed -i 's|maxage.*|maxage 14|g' /etc/logrotate.d/datasync-*").read()
		print('Completed setting log maxage to 14')

def rcDS(status, op = None):
	setVariables()
	spinner = set_spinner()

	if status == "start" and op == None:
		print('Starting Mobility.. ', end='')
		spinner.start(); time.sleep(.000001)
		d = subprocess.Popen(['%s' % rcScript, 'start'], stdout=subprocess.PIPE)
		c = subprocess.Popen(['rccron', 'start'], stdout=subprocess.PIPE)
		d.wait()
		c.wait()
		spinner.stop(); print()

	elif status == "start" and op == "nocron":
		print('Starting Mobility.. ', end='')
		spinner.start(); time.sleep(.000001)
		d = subprocess.Popen(['%s' % rcScript, 'start'], stdout=subprocess.PIPE)
		d.wait()
		spinner.stop(); print()

	elif status == "stop" and op == None:
		print('Stopping Mobility.. ', end='')
		spinner.start(); time.sleep(.000001)
		d = subprocess.Popen(['%s' % rcScript, 'stop'], stdout=subprocess.PIPE)
		c = subprocess.Popen(['rccron', 'stop'], stdout=subprocess.PIPE)
		d.wait()
		c.wait()
		pids = get_pid('/usr/bin/python')
		cpids = get_pid('cron')
		for pid in pids:
			kill_pid(int(pid), 9)
		for pid in cpids:
			kill_pid(int(cpid))
		spinner.stop(); print()

	elif status == "stop" and op == "nocron":
		print('Stopping Mobility.. ', end='')
		spinner.start(); time.sleep(.000001)
		d = subprocess.Popen(['%s' % rcScript, 'stop'], stdout=subprocess.PIPE)
		d.wait()
		pids = get_pid('/usr/bin/python')
		for pid in pids:
			kill_pid(int(pid), 9)
		spinner.stop(); print()

	elif status == "restart" and op == None:
		print('Restarting Mobility.. ', end='')
		spinner.start(); time.sleep(.000001)
		d = subprocess.Popen(['%s' % rcScript, 'stop'], stdout=subprocess.PIPE)
		c = subprocess.Popen(['rccron', 'stop'], stdout=subprocess.PIPE)
		d.wait()
		c.wait()
		pids = get_pid('/usr/bin/python')
		cpids = get_pid('cron')
		for pid in pids:
			kill_pid(int(pid), 9)
		for pid in cpids:
			kill_pid(int(cpid))
		d = subprocess.Popen(['%s' % rcScript, 'start'], stdout=subprocess.PIPE)
		c = subprocess.Popen(['rccron', 'start'], stdout=subprocess.PIPE)
		d.wait()
		c.wait()
		spinner.stop(); print()

def verifyUserMobilityDB(dbConfig, userConfig):
	# Check if user exists in mobility database
	logger.info('Checking for %s in mobility database' % userConfig['name'])
	name = {'user': userConfig['name']}
	conn = getConn(dbConfig, 'mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select distinct userid from users where userid ~* '(%(user)s[.|,].*)$' OR userid ilike '%(user)s' OR name ilike '%(user)s'" % name)
	validUser = cur.fetchall()
	cur.close()
	conn.close()
	for row in validUser:
		if row['userid'] != "":
			logger.debug("Found '%s' in mobility database" % row['userid'])
			userConfig['mName'] = row['userid']
			return True
	logger.warning('User %s not found in mobility database' % userConfig['name'])
	userConfig['mName'] = None
	return False

def verifyUserDataSyncDB(dbConfig, userConfig):
	# Check if user exists in datasync database
	logger.info('Checking for %s in datasync database' % userConfig['name'])
	name = {'user': userConfig['name']}
	conn = getConn(dbConfig, 'datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select distinct dn from targets where (\"dn\" ~* '(%(user)s[.|,].*)$' OR dn ilike '%(user)s' OR \"targetName\" ilike '%(user)s') AND disabled='0'" % name)
	validUser = cur.fetchall()
	cur.close()
	conn.close()
	for row in validUser:
		if row['dn'] != "":
			logger.debug("Found '%s' in datasync database" % row['dn'])
			userConfig['dName'] = row['dn']
			return True
	logger.warning('User %s not found in datasync database' % userConfig['name'])
	userConfig['dName'] = None
	return False

def get_username(userConfig):
	with open(dsappConf + '/special_char.cfg', 'r') as f:
		invalid = f.read().splitlines()
	del invalid[0] # Removes comment from list
	username = ""
	# Prompt user for username
	datasyncBanner(dsappversion)
	print ("Enter 'q' to cancel")
	while username == "":
		username = raw_input("UserID: ")
		if username == 'q' or username == 'Q':
			userConfig['name'] = None
			return False
		elif username in invalid:
			if not askYesOrNo("Invalid input. Try again"):
				userConfig['name'] = None
				return False
			else:
				username = ""
		elif username == "":
			if not askYesOrNo("No input. Try again"):
				userConfig['name'] = None
				return False
	userConfig['name'] = username
	return True

def verifyUser(dbConfig):
	userConfig = {}
	# Return a number based on conditions 
	get_username(userConfig)
	if userConfig['name'] is None:
		userConfig['mName'] = None
		userConfig['dName'] = None
		userConfig['verify'] = None
		return userConfig
	datasyncBanner(dsappversion)
	# Calculate verifyCount based on where user was found
	verifyCount = 0
	# 0 = no user found ; 2 = datasync only ; 1 = mobility only ; 3 = both database

	if verifyUserDataSyncDB(dbConfig, userConfig):
		verifyCount += 2

	if verifyUserMobilityDB(dbConfig, userConfig):
		verifyCount += 1

	if verifyCount == 0:
		userConfig['verify'] = 0
	elif verifyCount == 1:
		userConfig['verify'] = 1
	elif verifyCount == 2:
		userConfig['verify'] = 2
	elif verifyCount == 3:
		userConfig['verify'] = 3

	userConfig = getApplicationNames(userConfig, dbConfig)

	return userConfig

def confirm_user(userConfig, database = None):
	if userConfig['name'] == None:
		return False
	if database == 1:
		return True
	elif database == 'mobility' and userConfig['verify'] == 2:
		print ("%s not found in Mobility" % userConfig['name'])
		return False
	elif database == 'datasync' and userConfig['verify'] == 1:
		print ("%s not found in Mobility" % userConfig['name'])
		return False
	if userConfig['verify'] == 0:
		print ("%s not found in Mobility" % userConfig['name'])
		return False
	return True

def monitor_command(dbConfig, command, refresh):
	clear()
	conn = getConn(dbConfig, 'mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

	clearLine = "\033[1J" + "\033[H"
	states = {'1': 'Initial Sync   ', '2': 'Synced         ', '3': 'Syncing-Days+  ', '5': 'Failed         ', '6':'Delete         ', '7': 'Re-Init        ', '9': 'Sync Validate  ', '11': 'Requesting Init', '12': 'Requesting More'}
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
	except:
		logger.debug('Ending monitor')

	clear()
	cur.close()
	conn.close()

def monitor_syncing_users(dbConfig, refresh = 1):
	command = "SELECT state,userID FROM users WHERE state !='2'"
	monitor_command(dbConfig, command, refresh)

def monitorUser(dbConfig, userConfig = None, refresh = 1):
	if userConfig is None:
		userConfig = verifyUser(dbConfig)
	if confirm_user(userConfig, 'mobility'):
		command = "SELECT state,userID FROM users WHERE userid ilike '%%%s%%'" % userConfig['mName']
		monitor_command(dbConfig, command, refresh)

def setUserState(dbConfig, state):
	# verifyUser sets vuid variable used in setUserState and removeAUser functions
	userConfig = verifyUser(dbConfig)
	if confirm_user(userConfig, 'mobility'):
		conn = getConn(dbConfig, 'mobility')
		cur = conn.cursor()
		cur.execute("UPDATE users SET state = '%s' WHERE userid ilike '%%%s%%'" % (state, userConfig['mName']))
		logger.info("Set '%s' to state %s" % (userConfig['mName'], state))
		cur.close()
		conn.close()

		monitorUser(dbConfig, userConfig)

def file_mCleanup(filePath, fileCount):
	date = datetime.datetime.now().strftime("%H:%M:%S on %b %d, %Y")
	count = 0
	if os.path.isfile(filePath):
		with open(filePath, 'r') as f:
			lines = f.read().splitlines()
		with open(dsappLogs + '/mCleanup.log', 'a') as f:
			f.write("\n%s\n------- Removing %s attachments -------\n" % (date, fileCount))
			for i in xrange(len(lines)):
				removeF = mAttach + filestoreIdToPath.hashFileStoreID(lines[i])
				try:
					os.remove(removeF)
					f.write("Removed '%s'\n" % removeF)
					count += 1
				except OSError:
					f.write("Warning: file %s not found\n" % removeF)

			f.write("------- Complete : %s files removed -------" % count)

		os.remove(filePath)
		os.remove(dsappConf + '/fileIDs.dsapp')

def mCleanup(dbConfig, userConfig):
	print ("Mobility database cleanup:")
	spinner = set_spinner()
	uGuid = ""
	
	conn = getConn(dbConfig, 'mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

	# Get users mobility guid
	cur.execute("select guid from users where userid ~* '(%(name)s[.|,].*)$' OR name ilike '%(name)s' OR userid ilike '%(name)s'" % userConfig)
	data = cur.fetchall()
	for row in data:
		uGuid = row['guid']

	logger.debug("uGuid assigned '%s'" % uGuid)

	print ("Removing %s attachment maps from mobility.." % userConfig['name'])
	logger.info("Removing '%s' attachmentmaps from mobility" % userConfig['name'])

	# Delete attachmentmaps
	cur.execute("delete from attachmentmaps where userid='%s'" % uGuid)
	logger.debug("DELETE FROM attachmentmaps..")

	# Get filestoreIDs that are safe to delete
	print ("Obtaining list of file store IDs to remove..")
	logger.info("Obtaining list of filestoreid to remove..")
	cur.execute("SELECT filestoreid FROM attachments LEFT OUTER JOIN attachmentmaps ON attachments.attachmentid=attachmentmaps.attachmentid WHERE attachmentmaps.attachmentid IS NULL")
	fileID = cur.fetchall()

	# Write fileIDs to a file
	with open(dsappConf + '/fileIDs.dsapp', 'a') as f:
		for line in fileID:
			f.write(line['filestoreid']  + '\n')

	print ("Removing %s from mobility database.. " % userConfig['name'], end='')
	logger.info("Removing '%s' from mobility database started" % userConfig['name'])
	spinner.start(); time.sleep(.000001)
	time1 = time.time()

	# clean tables with users guid
	cur.execute("delete from foldermaps where deviceid IN (select deviceid from devices where userid='%s')" % uGuid)
	logger.debug("DELETE FROM foldermaps..")
	cur.execute("delete from deviceimages where userid='%s'" % uGuid)
	logger.debug("DELETE FROM deviceimages..")
	cur.execute("delete from syncevents where userid='%s'" % uGuid)
	logger.debug("DELETE FROM syncevents..")
	cur.execute("delete from deviceevents where userid='%s'" % uGuid)
	logger.debug("DELETE FROM deviceevents..")
	cur.execute("delete from devices where userid='%s'" % uGuid)
	logger.debug("DELETE FROM devices..")
	cur.execute("delete from users where guid='%s'" % uGuid)
	logger.debug("DELETE FROM users..")
	cur.execute("delete from attachments where attachmentid IN (select attachmentid from attachmentmaps where objectid in (select objectid from deviceimages where userid='%s'))" % uGuid)
	logger.debug("DELETE FROM attachments where attachmentid..")
	cur.execute("delete from attachments where filestoreid IN (SELECT filestoreid FROM attachments LEFT OUTER JOIN attachmentmaps ON attachments.attachmentid=attachmentmaps.attachmentid WHERE attachmentmaps.attachmentid IS NULL)")
	logger.debug("DELETE FROM attachments where filestoreid..")

	spinner.stop(); print()
	cur.close()
	conn.close()

	# Remove duplicate fileIDs
	count = 0
	lines_seen = set()
	outfile = open(dsappConf + '/uniq-fileIDs.dsapp', 'w')
	if os.path.isfile(dsappConf + '/fileIDs.dsapp'):
		spinner = set_spinner()
		print ("Creating list of files to remove.. ", end='')
		logger.debug("Remove any duplicates fileIDs")
		spinner.start(); time.sleep(.000001)
		for line in open(dsappConf + '/fileIDs.dsapp', 'r'):
			if line not in lines_seen: # No duplicates
				outfile.write(line)
				lines_seen.add(line)
				count += 1
		outfile.close()
		spinner.stop(); print()

	print ("Removing attachments..")
	logger.info("Removing %s attachments in background process" % count)
	# Clean up fileIDs in detached process
	filePath = dsappConf + '/uniq-fileIDs.dsapp'
	p = Process(target=file_mCleanup, args=(filePath, count,))
	p.start()

	time2 = time.time()
	logger.info("Removing '%s' from mobility database complete" % userConfig['name'])
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

def dCleanup(dbConfig, userConfig):
	print ("Datasync database cleanup:")
	spinner = set_spinner()
	uUser, psqlAppNameM, psqlAppNameG = "", "", ""

	conn = getConn(dbConfig, 'datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

	# Get user dn from targets table;
	cur.execute("select distinct dn from targets where (\"dn\" ~* '(%(name)s[.|,].*)$' OR dn ilike '%(name)s' OR \"targetName\" ilike '%(name)s') AND disabled='0'" % userConfig)
	data = cur.fetchall()
	for row in uUser:
		uUser = row['dn']

	# Get targetName from each connector
	cur.execute("select \"targetName\" from targets where (dn ~* '(%(name)s[.|,].*)$' OR dn ilike '%(name)s' OR \"targetName\" ilike '%(name)s') AND \"connectorID\"='default.pipeline1.groupwise'" % userConfig)
	data = cur.fetchall()
	for row in data:
		psqlAppNameG = row['targetName']

	cur.execute("select \"targetName\" from targets where (dn ~* '(%(name)s[.|,].*)$' OR dn ilike '%(name)s' OR \"targetName\" ilike '%(name)s') AND \"connectorID\"='default.pipeline1.mobility'" % userConfig)
	data = cur.fetchall()
	for row in data:
		psqlAppNameM = row['targetName']

	logger.debug("uUser assigned '%s'" % uUser)
	logger.debug("psqlAppNameG assigned '%s'" % psqlAppNameG)
	logger.debug("psqlAppNameM assigned '%s'" % psqlAppNameM)

	print ("Removing %s from datasync database.. " % userConfig['name'], end='')
	logger.info("Removing '%s' from datasync database started" % userConfig['name'])

	# Delete objectMappings, cache, membershipCache, folderMappings, and targets from datasync DB
	spinner.start(); time.sleep(.000001)
	time1 = time.time()
	cur.execute("delete FROM \"objectMappings\" WHERE \"objectID\" IN (SELECT \"objectID\" FROM \"objectMappings\" WHERE \"objectID\" ilike '%%|%s' OR \"objectID\" ilike '%%|%s' OR \"objectID\" ilike '%%|%s')" % (psqlAppNameG, psqlAppNameM, userConfig['name']))
	logger.debug('DELETE FROM objectMappings..')
	cur.execute("delete FROM consumerevents WHERE edata ilike '%%<sourceName>%s</sourceName>%%' OR edata ilike '%%<sourceName>%s</sourceName>%%'" % (psqlAppNameG, psqlAppNameM))
	logger.debug('DELETE FROM consumerevents..')
	cur.execute("delete FROM \"folderMappings\" WHERE \"targetDN\" ilike '(%s[.|,].*)$' OR \"targetDN\" ilike '%s'" % (userConfig['name'],uUser))
	logger.debug('DELETE FROM folderMappings..')
	cur.execute("delete FROM cache WHERE \"sourceDN\" ilike '(%s[.|,].*)$' OR \"sourceDN\" ilike '%s'" % (userConfig['name'],uUser))
	logger.debug('DELETE FROM cache..')
	cur.execute("delete FROM \"membershipCache\" WHERE (groupdn ilike '(%s[.|,].*)$' OR memberdn ilike '(%s[.|,].*)$') OR (groupdn ilike '%s' OR memberdn ilike '%s')" % (userConfig['name'], userConfig['name'], uUser, uUser))
	logger.debug('DELETE FROM membershipCache..')
	cur.execute("delete FROM targets WHERE dn ~* '(%(name)s[.|,].*)$' OR dn ilike '%(name)s' OR \"targetName\" ilike '%(name)s'" % userConfig)
	logger.debug('DELETE FROM targets..')
	time2 = time.time()
	logger.info("Removing '%s' from datasync database complete" % userConfig['name'])
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	spinner.stop(); print()

	cur.close()
	conn.close()

def remove_user(dbConfig, op = None):
	# Pass in 1 for op to skip user database check in confirm_user()
	userConfig = verifyUser(dbConfig)
	datasyncBanner(dsappversion)
	if op == 1:
		logger.debug("Skipping user database check")
		if confirm_user(userConfig, op):
			if askYesOrNo("Remove %s from datasync database" % userConfig['name']):
				dCleanup(dbConfig, userConfig)
			print()
			if askYesOrNo("Remove %s from mobility database" % userConfig['name']):
				mCleanup(dbConfig, userConfig)
	elif op == None:
		logger.debug("Checking user in database")
		if confirm_user(userConfig):

			# Set user to delete
			conn = getConn(dbConfig, 'datasync')
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
			conn = getConn(dbConfig, 'mobility')
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

			dCleanup(dbConfig, userConfig)
			print()
			mCleanup(dbConfig, userConfig)

def addGroup(dbConfig, ldapConfig):
	conn = getConn(dbConfig, 'datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

	datasyncBanner(dsappversion)
	ldapGroups = None
	ldapGroupMembership = {}

	logger.info("Obtaining all groups from Mobility")
	cur.execute("select distinct dn from targets where \"targetType\"='group' AND dn ilike 'cn=%%'")
	ldapGroups = cur.fetchall()

	print ("\nMobility Group(s):")
	for row in ldapGroups:
		print (row['dn'])

	print ("\nGroup Membership:")
	for group in ldapGroups:
		secure = "ldap"
		if ldapConfig['port'] == "636":
			secure = "ldaps"
		cmd = "/usr/bin/ldapsearch -x -H %s://%s -D %s -w %s -b %s | perl -p00e 's/\r?\n //g' | grep member: | cut -d \":\" -f 2 | sed 's/^[ \t]*//' | sed 's/^/\"/' | sed 's/$/\",\"'%s'\"/'" % (secure, ldapConfig['host'], ldapConfig['login'], ldapConfig['pass'], group['dn'], group['dn'])
		ldap = os.popen(cmd).read().strip()
		print(ldap)
		ldapGroupMembership[group['dn']] = ldap

	print ()
	if askYesOrNo("Does the above appear correct"):
		copy_cmd = "copy \"membershipCache\"(memberdn,groupdn) from STDIN WITH DELIMITER ',' CSV HEADER"
		cur.execute("delete from \"membershipCache\"")
		logger.info('Removing old memberhipCache data')
		with open(dsapptmp + '/ldapGroupMembership.dsapp' , 'a') as f:
			f.write("memberdn,groupdn\n")
			for group in ldapGroups:
				f.write(ldapGroupMembership[group['dn']])

		with open(dsapptmp + '/ldapGroupMembership.dsapp' ,'r') as f:
			logger.info("Updating membershipCache with current data")
			cur.copy_expert(sql=copy_cmd, file=f)
			
		os.remove (dsapptmp + '/ldapGroupMembership.dsapp')
		print ("\nGroup Membership has been updated\n")
		logger.info("Group membership has been updated")
		
	cur.close()
	conn.close()

	# TODO : Call function to fix reference cound / disabled

def updateMobilityFTP():
	datasyncBanner(dsappversion)
	if DoesServiceExist('ftp.novell.com', 21):
		print ("Mobility will restart during the upgrade")
		if askYesOrNo("Continue"):
			# Check FTP connectivity
			ds = raw_input("FTP Filename: ")
			dbuild = ds.split('.')[0]
			os.chdir('/root/Downloads')
			if dlfile('ftp://ftp.novell.com/outgoing/%s' % ds):

				# Get ISO name
				dsISO = file_content(ds)
				# Decompress file
				uncompressIt(ds)

				zypper = subprocess.Popen(["zypper", "rr", "mobility"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				zypper.wait()
				zypper = subprocess.Popen(["zypper", "addrepo", "iso:///?iso=%s&url=file:///root/Downloads" % dsISO[0], "mobility"], stdout=subprocess.PIPE)
				zypper.wait()

				dsUpdate('mobility')
	else:
		print ("Unable to connect to ftp.novell.com 21")

def checkNightlyMaintenance(config_files, mobilityConfig):
	global problem
	setVariables()
	problem = False

	print("Scanning logs for maintenance.. ")
	logger.info("Scannning logs for maintenance..")
	time1 = time.time()

	# Open files, and get content to print later
	dbSetting = []
	logReport = []
	with open(config_files['mconf'], 'r') as f:
		for line in f:
			if 'database' in line: dbSetting.append(line.strip())
	with open(mAlog, 'r') as f:
		for line in f:
			if 'Nightly maintenance' in line: logReport.append(line.strip())
	
	# If logReport is empty, check next 5 gziped logs
	if len(logReport) == 0:
		files = sorted(glob.glob(log +'/connectors/mobility-agent.*'), key=os.path.getctime)
		try:
			files.remove(log + '/connectors/mobility-agent.log')
		except:
			pass

		for file in files[-5:]:
			with contextlib.closing(gzip.open('%s' % file, 'r')) as f:
				for line in f:
					if 'Nightly maintenance' in line: logReport.append(line.strip())
			if len(logReport) != 0:
				break

	time2 = time.time()
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

	print ("\nNightly Maintenance Settings:")
	for line in dbSetting:
		print (line)

	if mobilityConfig['dbMaintenance'] != '1':
		problem = True
		print ("\nNightly Maintenance disabled\n")
	elif mobilityConfig['dbMaintenance'] == '1' and len(logReport) != 0:
		print ("\nNightly Maintenance History:")
		logger.info('Found maintenance history in: %s' % file)
		print (file)
		for line in logReport[-5:]:
			print (line)
	else:
		print ("Unable to find nightly maintenance in past logs")
		logger.info("Unable to find nightly maintenance in past logs")
		problem = True

def showStatus(dbConfig):
	# Pending sync items - Monitor
	data_found = False
	logger.info("Checking for pending events")
	conn = getConn(dbConfig, 'datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select state,count(*) from consumerevents where state!='1000' group by state")
	data = cur.fetchall()
	cur.close()
	conn.close()
	if len(data) != 0:
		print ("\nGroupWise-connector:")
		data_found = True
		logger.info("Found pending consumerevents")
		print (" state | count\n-------+-------")
		for row1 in data:
			print (" %s | %s " % (row['state'], row['count']))

	conn = getConn(dbConfig, 'mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select state,count(*) from syncevents where state!='1000' group by state")
	data = cur.fetchall()
	cur.close()
	conn.close()
	if len(data) != 0:
		print ("\nMobility-connector:")
		data_found = True
		logger.info("Found pending syncevents")
		print (" state | count\n-------+-------")
		for row1 in data:
			print (" %s | %s " % (row['state'], row['count']))

	if not data_found:
		print ("No pending events")
		logger.info("No pending events")

def indexDB(dbConfig):
	cmd = "PGPASSWORD=%(pass)s psql -U %(user)s datasync -c \"reindex database datasync\"" % dbConfig
	logger.info("Indexing datasync database..")
	time1 = time.time()
	i = subprocess.Popen(cmd, shell=True)
	i.wait()
	time2 = time.time()
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

	cmd = "PGPASSWORD=%(pass)s psql -U %(user)s mobility -c \"reindex database mobility\"" % dbConfig
	logger.info("Indexing mobility database..")
	time1 = time.time()
	i = subprocess.Popen(cmd, shell=True)
	i.wait()
	time2 = time.time()
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

def vacuumDB(dbConfig):
	cmd = "PGPASSWORD=%(pass)s vacuumdb -U %(user)s datasync --full -v" % dbConfig
	logger.info("Vacuuming datasync database..")
	time1 = time.time()
	v = subprocess.Popen(cmd, shell=True)
	v.wait()
	time2 = time.time()
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

	cmd = "PGPASSWORD=%(pass)s vacuumdb -U %(user)s mobility --full -v" % dbConfig
	logger.info("Vacuuming mobility database..")
	time1 = time.time()
	v = subprocess.Popen(cmd, shell=True)
	v.wait()
	time2 = time.time()
	logger.info("Operation took %0.3f ms" % ((time2 - time1) * 1000))

def changeDBPass(dbConfig, config_files, XMLconfig):
	datasyncBanner(dsappversion)
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

		#Get Encrypted password from user input
		inputEncrpt = encryptMSG(p_input)

		print ("Changing database password..")
		conn = getConn(dbConfig, 'postgres')
		cur = conn.cursor()
		logger.info("Changeing datasync_user database password")
		try:
			cur.execute("ALTER USER datasync_user WITH password \'%s\'" % p_input)
		except:
			print ("Failed to change database password")
			logger.error("Failed to change datasync_user database password")
			sys.exit(1)

		cur.close()
		conn.close()
		# Backup conf files
		backup_config_files(config_files, 'changeDBPass')

		# Update XML files with new password
		if isProtected(XMLconfig['ceconf'], './/configengine/database/protected'):
			setXML('.//configengine/database/password', XMLconfig['ceconf'], inputEncrpt, config_files['ceconf'])
		else:
			setXML('.//configengine/database/password', XMLconfig['ceconf'], p_input, config_files['ceconf'])
		logger.info("Updated database password in %s" % config_files['ceconf'])

		if isProtected(XMLconfig['econf'], './/settings/database/protected'):
			setXML('.//settings/database/password', XMLconfig['econf'], inputEncrpt, config_files['econf'])
		else:
			setXML('.//settings/database/password', XMLconfig['econf'], p_input, config_files['econf'])
		logger.info("Updated database password in %s" % config_files['econf'])

		if isProtected(XMLconfig['mconf'], './/settings/custom/protected'):
			setXML('.//settings/custom/dbpass', XMLconfig['mconf'], inputEncrpt, config_files['mconf'])
		else:
			setXML('.//settings/custom/dbpass', XMLconfig['mconf'], p_input, config_files['mconf'])
		logger.info("Updated database password in %s" % config_files['mconf'])

		print ("\nDatabase password updated. Please restart mobility.")

def changeAppName(dbConfig):
	datasyncBanner(dsappversion)
	userConfig = verifyUser(dbConfig)
	if confirm_user(userConfig, 'datasync'):
		conn = getConn(dbConfig, 'datasync')
		cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

		# Assign application names from database to default variables
		cur.execute("select \"targetName\" from targets where dn ilike '%%%s%%' AND \"connectorID\"='default.pipeline1.mobility'" % userConfig['name'])
		defaultMAppName = cur.fetchall()[0]['targetName']

		cur.execute("select \"targetName\" from targets where dn ilike '%%%s%%' AND \"connectorID\"='default.pipeline1.groupwise'" % userConfig['name'])
		defaultGAppName = cur.fetchall()[0]['targetName']

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
				
				# pdates users application names with variable entries
				cur.execute("UPDATE targets set \"targetName\"='%s' where dn ilike '%%%s%%' AND \"connectorID\"='default.pipeline1.mobility'" % (mAppName, userConfig['name']))
				logger.info("Set mobility application name to: %s" % mAppName)
				cur.execute("UPDATE targets set \"targetName\"='%s' where dn ilike '%%%s%%' AND \"connectorID\"='default.pipeline1.groupwise'" % (gAppName, userConfig['name']))
				logger.info("Set groupwise application name to: %s" % gAppName)

				print ("\nRestart mobility to pick up changes.")
		else:
			print ("Unable to find application names")
			logger.warning("Unalbe to find all application names")

		cur.close()
		conn.close()

def reinitAllUsers(dbConfig):
	datasyncBanner(dsappversion)
	print (textwrap.fill("Note: During the re-initialize, users will not be able to log in. This may take some time.", 80))
	if askYesOrNo("Are you sure you want to re-initialize all the users"):
		conn = getConn(dbConfig, 'mobility')
		cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
		cur.execute("update users set state = '7'")

		cur.close()
		conn.close()
		print ("\nAll users have been set to re-initialize")


####### Certificate functions #######

def certPath():
	certPath = autoCompleteInput("Enter path to store certificate files: ")
	if promptVerifyPath(certPath):
		return certPath
	return ""


def newCertPass():
	keyPass = getpass.getpass("Enter password for private key: ")
	confirmPass = getpass.getpass("Confirm password: ")
	if keyPass != confirmPass:
		print ("\nPasswords do not match")
		logger.warning("Passwords do not match")
		return
	logger.info("Private key password created")
	return keyPass

def getCommonName(csrFile):
	cmd = "openssl req -in %s -text -noout" % csrFile
	out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
	out.wait()
	pout = p = out.communicate()[0]
	search = re.search('CN=.*', pout)
	return search.group().split('=')[1]

def signCert(path, csr, key, keyPass, commonName, sign = False):
	print ("\nSigning certificate")
	logger.info("Signing certificate..")
	if os.path.isfile(path + '/' + csr) and os.path.isfile(path + '/' + key):
		certDays = raw_input("Certificate Validity Period (Days): ")
		if certDays:
			certDays = '730'

		crt = "%s.crt" % commonName
		cmd = "openssl x509 -req -days %s -in %s/%s -signkey %s/%s -out %s/%s -passin pass:%s &>/dev/null" % (certDays, path, csr, path, key, path, crt, keyPass)
		logger.debug("Signing %s" % csr)
		signed = subprocess.call(cmd, shell=True)

		print ("Signed Server Certificate: %s/%s" % (path, crt))
		logger.info("Signed server certificate at %s" % path)
	else:
		print ("Unable to locate certificate files")

	if sign:
		eContinue()
		createPEM(sign, commonName, keyPass, key, crt, path)

def createCSRKey(sign = False):
	datasyncBanner(dsappversion)
	#Start of Generate CSR and Key script.
	path = certPath()
	if path:
		# Remove '/' from end of path
		path = path.rstrip('/')

		print ("\nGenerating a private key and certificate signing request (CSR)")
		logger.info("Generating a private key and CSR")
		keyPass = newCertPass()
		print ()

		cmd = "openssl genrsa -passout pass:%s -des3 -out %s/server.key 2048" % (keyPass, path)
		logger.debug("Creating private key..")
		key = subprocess.call(cmd, shell=True)
		cmd = "openssl req -sha256 -new -key %s/server.key -out %s/server.csr -passin pass:%s" % (path, path, keyPass)
		logger.debug("Creating certificate signing request..")
		csr = subprocess.call(cmd, shell=True)
		
		csr = '%s/server.csr' % path
		commonName = getCommonName(csr)
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

		if sign:
			eContinue()
			signCert(path, csr, key, keyPass, commonName, sign)

def createPEM(sign = None, commonName = None, keyPass = None, key = None, crt = None, path = None):
	datasyncBanner(dsappversion)
	print ("Creating PEM..")

	# Ask for files/path if not self-signed
	if not sign:
		print ("Please provide the private key, the public certificate, and any intermediate certificate or bundles.\n")
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
		cmd = "openssl rsa -in %s/%s -check -noout -passin pass:" % (path,key)
		chk = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		valid, error = chk.communicate()
		if error:
			# Check the private key password
			keyPass = getpass.getpass("Private key passphrase: ")
			cmd = "openssl rsa -in %s/%s -check -noout -passin pass:%s" % (path,key,keyPass)
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
		cmd = "dos2unix %s/%s &>/dev/null" % (path,caFile)
		tmp = subprocess.call(cmd, shell=True)

	# dos2unix the public certificate and private key
	cmd = "dos2unix %s/%s %s/%s &>/dev/null" % (path,key,path,crt)
	tmp = subprocess.call(cmd, shell=True)

	# Removing password from Private Key, if it contains one
	cmd = "openssl rsa -in %s/%s -out %s/nopassword.key -passin pass:%s &>/dev/null" % (path,key,path,keyPass)
	tmp = subprocess.call(cmd, shell=True)
	logger.debug("Creating %s/nopassword.key for mobility.pem" % path)

	# Remove any pervious mobility.pem files
	if os.path.isfile('%s/mobility.pem' % path):
		os.remove('%s/mobility.pem' % path)
		logger.debug("Removing previous %s/mobility.pem" % path)

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

	print ("\nPEM created at: %s/mobility.pem" % path)
	logger.info("PEM created at: %s/mobility.pem" % path)

	if askYesOrNo("Install PEM"):
		logger.debug("Running certificate install..")
		configureMobilityCerts(path)

def configureMobilityCerts(path):
	certInstall = False
	datasyncBanner(dsappversion)

	if askYesOrNo("Implement pem certificate with Mobility devices"):
		shutil.copy(path + '/mobility.pem', dirVarMobility + '/device/mobility.pem')
		print ("Copied mobility.pem to %s/device/mobility.pem" % dirVarMobility)
		logger.info("Copied %s/mobility.pem to %s/device/mobility.pem" % (path, dirVarMobility))
		certInstall = True

	if askYesOrNo("\nImplement pem certificate with Mobility web admin"):
		shutil.copy(path + '/mobility.pem', dirVarMobility + '/webadmin/server.pem')
		print ("Copied mobility.pem to %s/webadmin/server.pem" % dirVarMobility)
		logger.info("Copied %s/mobility.pem to %s/webadmin/server.pem" % (path, dirVarMobility))
		certInstall = True

	if certInstall:
		if askYesOrNo("\nDo you want to restart Mobility services now"):
			rcDS('restart')
		else:
			print ("Note: Mobility services will need to be restarted for the PEM to become active")

def verifyCertifiateMatch(key = None, keyPass = None, crt = None, path = None):
	if key == None and crt == None and path == None:
		datasyncBanner(dsappversion)
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
	cmd = "openssl x509 -noout -modulus -in %s/%s | openssl md5" % (path, crt)
	tmp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	crtMD5_good, crtMD5_err = tmp.communicate()
	if crtMD5_err:
		print ("Unable to load certificate")
		logger.warning("Unable to load certificate")
		return False

	# MD5 of private key
	if keyPass != None:
		cmd = "openssl rsa -noout -modulus -in %s/%s -passin pass:%s | openssl md5" % (path, key, keyPass)
	else:
		cmd = "openssl rsa -noout -modulus -in %s/%s | openssl md5" % (path, key)
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


def checkLDAP(XMLconfig ,ldapConfig):
	if not (ldapConfig['port'] or ldapConfig['login'] or ldapConfig['host'] or ldapConfig['pass']) or (ldapConfig['port'] == None or ldapConfig['login'] == None or ldapConfig['host'] == None or ldapConfig['pass'] == None):
		print ("Unable to determine ldap variables")
		logger.warning("Unable to determine ldap variables")
		return False

	if ldapConfig['secure'] == 'false':
		cmd = "/usr/bin/ldapsearch -x -H ldap://%(host)s -D %(login)s -w %(pass)s %(login)s" % ldapConfig
	elif ldapConfig['secure'] == 'true':
		cmd = "/usr/bin/ldapsearch -x -H ldaps://%(host)s -D %(login)s -w %(pass)s %(login)s" % ldapConfig

	logger.info("Testing LDAP connection")
	log_cmd = cmd.replace("-w " + ldapConfig['pass'],"-w *******")
	logger.debug("LDAP test command: %s" % log_cmd)
	ldapCheck = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	ldapCheck.wait()
	out, err = ldapCheck.communicate()
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

def updateFDN(dbConfig, XMLconfig, ldapConfig):
	datasyncBanner(dsappversion)
	if checkLDAP(XMLconfig, ldapConfig):
		userConfig = verifyUser(dbConfig)
		if userConfig['verify'] != 0:
			if userLdapOrGw(userConfig, 'ldap'):
				multiple = False
				print ("Searching LDAP...")
				userDN = []

				if ldapConfig['secure'] == 'false':
					cmd = "/usr/bin/ldapsearch -x -H ldap://%s -D %s -w %s -b %s" % (ldapConfig['host'], ldapConfig['login'], ldapConfig['pass'], userConfig['dName'])
				elif ldapConfig['secure'] == 'true':
					cmd = "/usr/bin/ldapsearch -x -H ldaps://%s -D %s -w %s -b %s" % (ldapConfig['host'], ldapConfig['login'], ldapConfig['pass'], userConfig['dName'])

				tmp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				out, err = tmp.communicate()
				search = re.search('dn:.*', out)
				if search:
					userDN.append((search.group().split(' ')[1]))
				if len(userDN) != 0:
					print (list(set(userDN))[0])
				else:
					print ("Unable to find LDAP user '%(name)s' at: %(dName)s" % userConfig)
					logger.warning("Unable to find LDAP user '%(name)s' at: %(dName)s" % userConfig)
					if askYesOrNo("Expand search"):
						print ("\nSearching LDAP...")
						userDN = []
						for container in ldapConfig['user']:
							if ldapConfig['secure'] == 'false':
								cmd = "/usr/bin/ldapsearch -x -H ldap://%s -D %s -w %s -b %s cn=%s" % (ldapConfig['host'], ldapConfig['login'], ldapConfig['pass'], container, userConfig['name'])
							elif ldapConfig['secure'] == 'true':
								cmd = "/usr/bin/ldapsearch -x -H ldaps://%s -D %s -w %s -b %s cn=%s" % (ldapConfig['host'], ldapConfig['login'], ldapConfig['pass'], container, userConfig['name'])
							tmp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
							out, err = tmp.communicate()
							search = re.findall('dn:.*', out)
							for dn in search:
								userDN.append(dn.split(' ')[1])
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
					conn = getConn(dbConfig, 'datasync')
					cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
					cur.execute("update targets set dn='%s' where dn='%s' or dn='%s'" % (userNewDN, userConfig['dName'], userConfig['mName']))
					cur.execute("update cache set \"sourceDN\"='%s' where \"sourceDN\"='%s' or \"sourceDN\"='%s'" % (userNewDN, userConfig['dName'], userConfig['mName']))
					cur.execute("update \"folderMappings\" set \"targetDN\"='%s' where \"targetDN\"='%s' or \"targetDN\"='%s'" % (userNewDN, userConfig['dName'], userConfig['mName']))
					cur.execute("update \"membershipCache\" set memberdn='%s' where memberdn='%s' or memberdn='%s'" % (userNewDN, userConfig['dName'], userConfig['mName']))
					cur.close()
					conn.close()
					# Connect to mobility database to change FDN
					conn = getConn(dbConfig, 'mobility')
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
			print ("No such user '%s'" % userConfig['name'])
			logger.warning("User '%s' not found in databases" % userConfig['name'])

def getApplicationNames(userConfig, dbConfig):
	conn = getConn(dbConfig, 'datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)

	cur.execute("select \"targetName\" from targets where dn='%s' and \"connectorID\"='default.pipeline1.mobility'" % userConfig['dName'])
	data = cur.fetchall()
	for row in data:
		userConfig['mAppName'] = row['targetName']

	cur.execute("select \"targetName\" from targets where dn='%s' and \"connectorID\"='default.pipeline1.groupwise'" % userConfig['dName'])
	data = cur.fetchall()
	for row in data:
		userConfig['gAppName'] = row['targetName']

	cur.close()
	conn.close()
	return userConfig

##################################################################################################
#	Patch / FTF Fixes
##################################################################################################

def getExactMobilityVersion():
	with open(version, 'r') as f:
		mVersion = f.read().translate(None, '.')
	return mVersion.rstrip()

def ftfPatchlevel(ftpFile, files):
	patchFile = dsappConf + '/patch-file.conf'

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

def ftfPatchlevelCheck(ftpFile):
	patchFile = dsappConf + '/patch-file.conf'
	if not os.path.isfile(patchFile):
		return False
	else:
		with open(patchFile, 'r') as f:
			patchFileContent = f.read()
		print (patchFileContent)
		if ftpFile in patchFileContent:
			datasyncBanner(dsappversion)
			print ("Patch %s has already been applied" % ftpFile)
			return True

# def checkVersion():
# 	if [ "$1" == "$daVersion" ]; then
# 		info "\nVersion check ${bGREEN}passed${NC}.\n"
# 		return 0;
# 	else
# 		error "This patch is intended for version $1, the server is running version $daVersion\n"
# 		return 1;
