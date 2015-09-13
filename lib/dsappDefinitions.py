from __future__ import print_function
import os,base64,binascii,sys,signal,select,getpass,shutil,fileinput,glob,atexit,time,datetime,itertools
import subprocess,socket,re,rpm,contextlib
import tarfile, zipfile
import thread, threading
from pipes import quote
from cStringIO import StringIO
from urllib2 import urlopen, URLError, HTTPError
from lxml import etree
from xml.parsers.expat import ExpatError
import logging, logging.config
import ConfigParser
Config = ConfigParser.ConfigParser()

sys.path.append('./lib')
import spin
import psycopg2
import getch
getch = getch._Getch()

# NOTE : Get function Name
# print (sys._getframe().f_code.co_name)

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

# Misc variables
ds_20x= 2000
ds_21x = 2100

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (dsappConf))
logger = logging.getLogger(__name__)

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

def get_pid(name):
	return os.popen('pgrep %s' % (name)).read().split()

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
			result = os.popen('echo %s | openssl enc -d -aes-256-cbc -a -k `hostname -f` 2>%s/decode_error' % (quote(msg),dsapptmp)).read().rstrip()
	else:
		if encode:
			result = base64.urlsafe_b64encode(os.popen('echo -n %s | openssl enc -aes-256-cbc -a -k %s' % (quote(msg),host)).read().rstrip())
		else:
			msg = base64.urlsafe_b64decode(msg)
			result = os.popen('echo %s | openssl enc -d -aes-256-cbc -a -k %s 2>%s/decode_error' % (quote(msg),host,dsapptmp)).read().rstrip()

	# Check for errors
	if os.path.isfile(dsapptmp + '/decode_error') and os.stat(dsapptmp + '/decode_error').st_size != 0 and path is not None:
		logger.error('bad decrypt - error decoding %s' % (path))
		os.remove(dsapptmp + '/decode_error')

		# TODO: Prompt user to attempt to fix files
		print ('\ndsapp has encountered an error. See log for more details')
		sys.exit(1)
	elif result:
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

def backup_config_files(list,fname=None):
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
		ds.logger.info('Successfully connected to postgresql [user=%s,pass=******]' % (dbConfig['user']))
		conn.close()
	except:
		print ('\ndsapp has encountered an error. See log for more details')
		logger.error('Unable to connect to postgresql [user=%s,pass=******]' % (dbConfig['user']))
		return False
	return True
		# TODO: Add option for connection failure

	# cur = conn.cursor()
	# cur.execute("""SELECT dn from targets""")
	# for row in rows:
	# 	print "   ", row[0]

	# var['command'] = '"SELECT dn from targets;"| tr -d \' \''
	# check = 'PGPASSWORD=%(password)s psql -d %(db)s -U %(user)s -h %(host)s -p %(port)s -c %(command)s' % var
	# cmd = subprocess.Popen(check, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	# result = cmd.wait()

def getConn(dbConfig):
	try:
		conn = psycopg2.connect("dbname='postgres' user='%s' host='%s' password='%s'" % (dbConfig['user'],dbConfig['host'],dbConfig['pass']))
	except:
		return None
	return conn

def dropDatabases(dbConfig):
	conn = getConn(dbConfig)
	Config.read(dsappSettings)
	mobile_version = Config.get('Misc', 'mobility.version')
	mobile_version = int(mobile_version)

	#Dropping Tables
	print ("Dropping datasync database")
	# CODE HERE
	print ("Dropping mobility database")
	# CODE HERE
	if mobile_version > ds_20x:
		print ("Dropping dsmonitor database")
	# 	# CODE HERE