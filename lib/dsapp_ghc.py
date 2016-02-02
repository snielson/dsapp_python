# Written by Shane Nielson <snielson@projectuminfinitas.com>
<<<<<<< HEAD

=======
>>>>>>> origin/Development
from __future__ import print_function
import os
import sys
import socket
import subprocess
import datetime
import time
import logging, logging.config
from multiprocessing import Process, Queue
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
import dsapp_Definitions as ds
import dsapp_Soap as dsSoap
<<<<<<< HEAD
import ntplib
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

# Misc variables
serverinfo = "/etc/*release"
initScripts = "/etc/init.d/"
rpminfo = "datasync"
dsapp_tar = "dsapp.tgz"
isNum = '^[0-9]+$'
ds_1x= 1
ds_2x = 2
ds_14x = 14
rcScript = None
mobilityVersion = 0
version = "/opt/novell/datasync/version"
<<<<<<< HEAD

# Global variables
silent = None
mobile_serviceCheck = True
web_serviceCheck = True
serverDateCheck = True
=======
silent = None
>>>>>>> origin/Development

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

# System logs / settings
messages = "/var/log/messages"
warn = "/var/log/warn"
proxyConf = "/etc/sysconfig/proxy"

# dsapp Conf / Logs
dsappSettings = dsappConf + "/setting.cfg"
dsappLogSettings = dsappConf + "/logging.cfg"
dsappLog = dsappConf + "/dsapp.log"
ghcLog = dsappLogs + "/generalHealthCheck.log"

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (dsappConf))
logger = logging.getLogger('dsapp_Definitions')

# Read Config
Config.read(dsappSettings)
dsappversion = Config.get('Misc', 'dsapp.version')
dsHostname = Config.get('Misc', 'hostname')

# Text color formats
colorGREEN = "\033[01;32m{0}\033[00m"
colorRED = "\033[01;31m{0}\033[00m"
colorYELLOW = "\033[01;33m{0}\033[00m"
colorBLUE = "\033[01;34m{0}\033[00m"

# Printing Columns
COL1 = "{0:35}"

##################################################################################################
#  General Health Check definitions
##################################################################################################

<<<<<<< HEAD
def generalHealthCheck(mobilityConfig, gwConfig, XMLconfig ,ldapConfig, dbConfig, trustedConfig, config_files, webConfig, ghc_silent=False):
	global silent
	silent = ghc_silent
	if not silent:
		ds.datasyncBanner(dsappversion)
=======
def generalHealthCheck(mobilityConfig, gwConfig, XMLconfig ,ldapConfig, dbConfig, trustedConfig, config_files, ghc_silent=False):
	global silent
	silent = ghc_silent
	ds.datasyncBanner(dsappversion)
>>>>>>> origin/Development
	DATE = datetime.datetime.now().strftime('%c')

	# Rewrite health check log with timestamp and version
	with open(ghcLog, 'w') as log:
		log.write("##########################################################\n#  General Health Check\n##########################################################\n")
		log.write("Gathered by dsapp v%s on %s\n\n" % (dsappversion, DATE))
	logger.info("Starting General Health Check..")
	time1 = time.time()

	# Get system RPMs in background
	rpm_queue = Queue()
	rpm_process = Process(target=ds.queue_getRPMs, args=(rpm_queue,))
	rpm_process.start()

	# Begin Health Checks
<<<<<<< HEAD
	ghc_checkServices(mobilityConfig, gwConfig, webConfig)
=======
	ghc_checkServices(mobilityConfig, gwConfig)
>>>>>>> origin/Development
	ghc_checkLDAP(XMLconfig ,ldapConfig)
	# ghc_checkPOA
	ghc_checkTrustedApp(trustedConfig, gwConfig)
	ghc_checkReqXMLs()
	ghc_checkXML()
	ghc_checkPSQLConfig()
	ghc_checkRPMSave()
	ghc_checkProxy()
	ghc_checkDiskSpace()
	ghc_checkMemory(dbConfig)
	ghc_checkVMWare()
	ghc_checkConfig()
	ghc_checkUpdateSH(dbConfig)
	ghc_checkManualMaintenance(dbConfig)
	ghc_checkReferenceCount(dbConfig)
	ghc_checkUserFDN(dbConfig, XMLconfig ,ldapConfig)
	ghc_verifyDatabaseIntegrity(dbConfig)
	ghc_verifyTargetsIntegrity(dbConfig)

	# # Slower checks...
	qhc_rpms = rpm_queue.get()
	rpm_process.join() # Make sure rpm_process is done before continuing
	ghc_checkRPMs(qhc_rpms)
	ghc_checkDiskIO()
	ghc_verifyNightlyMaintenance(config_files, mobilityConfig)

	# # Lots of information...
<<<<<<< HEAD
	ghc_verifyServerDate()
	ghc_verifyCertificates(mobilityConfig, webConfig)
=======
	# ghc_verifyCertificates
>>>>>>> origin/Development

	time2 = time.time()
	logger.info("General Health Check took %0.3f ms" % ((time2 - time1) * 1000))

	# Prompt View Logs

	if not silent:
		print ('\n')
		if ds.askYesOrNo("Do you want to view the log file"):
			cmd = "less %s" % ghcLog
			subprocess.call(cmd, shell=True)

		print ("Log created at: %s" % ghcLog)


###  Utility definitions for General Health Checks ###
def ghc_util_NewHeader(header):
	global silent
	if not silent:
		print (COL1.format("\n%s  " % header), end='')
	logger.info("GHC : %s" % header)
	with open(ghcLog, 'a') as log:
		log.write("==========================================================\n%s\n==========================================================\n" % header)

def ghc_util_passFail(result, msg=None):
	global silent
	with open(ghcLog, 'a') as log:
		if msg is not None:
			log.write(msg)

		if result == 'failed':
			if not silent:
				print (colorRED.format("Failed"), end='')
	 		log.write("\nFailed\n\n")
	 	elif result == 'warning':
	 		if not silent:
		 		print (colorYELLOW.format("Warning"), end='')
	 		log.write("\nWarning\n\n")
	 	elif result == 'skipped':
	 		if not silent:
		 		print (colorBLUE.format("Skipped"), end='')
			log.write("\nSkipped\n\n")
	 	elif result == 'passed':
	 		if not silent:
		 		print (colorGREEN.format("Passed"), end='')
			log.write("\nPassed\n\n")

def ghc_util_checkStatus(agent):
	cmd = "rc%s status" % (agent)
	time1 = time.time()
	logger.debug("Checking %s status" % agent)
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	p.wait()
	out = p.communicate()
	with open(ghcLog, 'a') as log:
		log.write(out[0])
		if out[1]:
			log.write(out[1])

	time2 = time.time()
	logger.debug("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	if 'running' not in out[0]:
		return False
	else:
		return True

def ghc_util_checkPostgresql():
	cmd = "rcpostgresql status"
	time1 = time.time()
	logger.debug("Checking Postgresql status")
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	p.wait()
	out = p.communicate()
	with open(ghcLog, 'a') as log:
		log.write(out[0])
		if out[1]:
			log.write(out[1])

	time2 = time.time()
	logger.debug("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	if 'running' not in out[0]:
		return False
	else:
		return True

def ghc_util_checkMobility(mobilityConfig):
	result = False
	cmd = "netstat -pan | grep LISTEN | grep :%s" % mobilityConfig['mPort']
	time1 = time.time()
	logger.debug("Checking port %s listener" % mobilityConfig['mPort'])
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
	p.wait()
	with open(ghcLog, 'a') as log:
		try:
			listener = p.communicate()[0].split('/')[1].strip()
		except:
			listener = None

		if listener == 'python':
			result = True
			log.write("\nMobility Connector listening on port %s: %s" % (mobilityConfig['mPort'], result))
		elif listener == 'httpd2-prefork':
			result = False
			log.write("\nApache2 listening on port %s: %s" % (mobilityConfig['mPort'], result))
		elif listener != 'python' or listener is None:
			result = False
			log.write("\nMobility Connector not listening on port %s: %s" % (mobilityConfig['mPort'], result))

	time2 = time.time()
	logger.debug("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	return result

def ghc_util_checkGroupWise(gwConfig):
	result = False
	cmd = "netstat -pan | grep LISTEN | grep :%s" % gwConfig['gport']
	time1 = time.time()
	logger.debug("Checking port %s listener" % gwConfig['gport'])
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
	p.wait()
	with open(ghcLog, 'a') as log:
		try:
			listener = p.communicate()[0].split('/')[1].strip()
		except:
			listener = None

		if listener == 'python':
			result = True
<<<<<<< HEAD
			log.write("\nGroupWise Connector listening on port %s: %s" % (gwConfig['gport'], result))
		elif listener != 'python' or listener is None:
			result = False
			log.write("\nGroupWise Connector not listening on port %s: %s" % (gwConfig['gport'], result))

	time2 = time.time()
	logger.debug("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	return result

def ghc_util_checkWebAdmin(webConfig):
	result = False
	cmd = "netstat -pan | grep LISTEN | grep :%s" % webConfig['port']
	time1 = time.time()
	logger.debug("Checking port %s listener" % webConfig['port'])
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
	p.wait()
	with open(ghcLog, 'a') as log:
		try:
			listener = p.communicate()[0].split('/')[1].strip()
		except:
			listener = None

		if listener == 'python':
			result = True
			log.write("\nWeb Admin listening on port %s: %s\n" % (webConfig['port'], result))
		elif listener != 'python' or listener is None:
			result = False
			log.write("\nWeb Admin not listening on port %s: %s\n" % (webConfig['port'], result))
=======
			log.write("\nGroupWise Connector listening on port %s: %s\n" % (gwConfig['gport'], result))
		elif listener != 'python' or listener is None:
			result = False
			log.write("\nGroupWise Connector not listening on port %s: %s\n" % (gwConfig['gport'], result))
>>>>>>> origin/Development

	time2 = time.time()
	logger.debug("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	return result

def ghc_util_checkMobPortConnectivity(mobilityConfig):
	result = False
	cmd = "netcat -z -w 5 %s %s -v" % (mobilityConfig['mlistenAddress'], mobilityConfig['mPort'])
	time1 = time.time()
	logger.debug("Checking port %s connectivity on %s" % (mobilityConfig['mPort'], mobilityConfig['mlistenAddress']))
	p = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE)
	p.wait()
	with open(ghcLog, 'a') as log:
		try:
			listener = p.communicate()[1].split(' ')[-1].strip()
		except:
			listener = None

		if 'open' in listener:
			result = True
			log.write("\nConnection successful on port %s\n" % mobilityConfig['mPort'])
		elif 'timed out' in listener or listener is None:
			result = False
			log.write("\nConnection timed out on port %s\n" % mobilityConfig['mPort'])
		elif 'refused' in listener or listener is None:
			result = False
			log.write("\nConnection refused on port %s\n" % mobilityConfig['mPort'])

	time2 = time.time()
	logger.debug("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	return result

def ghc_util_checkGWPortConnectivity(gwConfig):
	result = False
	cmd = "netcat -z -w 5 %s %s -v" % (gwConfig['sListenAddress'], gwConfig['gport'])
	time1 = time.time()
	logger.debug("Checking port %s connectivity on %s" % (gwConfig['gport'], gwConfig['sListenAddress']))
	p = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE)
	p.wait()
	with open(ghcLog, 'a') as log:
		try:
			listener = p.communicate()[1].split(' ')[-1].strip()
		except:
			listener = None

		if 'open' in listener:
			result = True
			log.write("Connection successful on port %s\n" % gwConfig['gport'])
		elif 'timed out' in listener or listener is None:
			result = False
			log.write("Connection timed out on port %s\n" % gwConfig['gport'])
		elif 'refused' in listener or listener is None:
			result = False
			log.write("Connection refused on port %s\n" % gwConfig['gport'])

	time2 = time.time()
	logger.debug("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	return result

<<<<<<< HEAD
def ghc_util_checkWebPortConnectivity(webConfig):
	result = False
	cmd = "netcat -z -w 5 %s %s -v" % (webConfig['ip'], webConfig['port'])
	time1 = time.time()
	logger.debug("Checking port %s connectivity on %s" % (webConfig['port'], webConfig['ip']))
	p = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE)
	p.wait()
	with open(ghcLog, 'a') as log:
		try:
			listener = p.communicate()[1].split(' ')[-1].strip()
		except:
			listener = None

		if 'open' in listener:
			result = True
			log.write("Connection successful on port %s\n" % webConfig['port'])
		elif 'timed out' in listener or listener is None:
			result = False
			log.write("Connection timed out on port %s\n" % webConfig['port'])
		elif 'refused' in listener or listener is None:
			result = False
			log.write("Connection refused on port %s\n" % webConfig['port'])

	time2 = time.time()
	logger.debug("Operation took %0.3f ms" % ((time2 - time1) * 1000))
	return result

=======
>>>>>>> origin/Development
def ghc_util_subprocess(cmd, error=False):
	if not error:
		p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
		p.wait()
		out = p.communicate()
	elif error:
		p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		p.wait()
		out = p.communicate()
	return out

<<<<<<< HEAD
def ghc_checkServices(mobilityConfig, gwConfig, webConfig):
	ghc_util_NewHeader("Checking Mobility Services..")
	problem = False
	global mobile_serviceCheck
	global web_serviceCheck
=======
def ghc_checkServices(mobilityConfig, gwConfig):
	ghc_util_NewHeader("Checking Mobility Services..")
	problem = False
>>>>>>> origin/Development

	# Finds all datasync scripts in /etc/inid.d. Appends them to datasync_scripts
	datasync_scripts = []
	for file in os.listdir(initScripts):
		if 'datasync-' in file:
			datasync_scripts.append(file)

	# datasync_scripts = ['datasync-configengine', 'datasync-monitorengine', 'datasync-webadmin', 'datasync-connectors', 'datasync-syncengine']

	for agent in datasync_scripts:
		if not ghc_util_checkStatus(agent):
			problem = True
	if not ghc_util_checkPostgresql():
		problem = True
	if not ghc_util_checkMobility(mobilityConfig):
		problem = True
<<<<<<< HEAD
		mobile_serviceCheck = False
	if not ghc_util_checkGroupWise(gwConfig):
		problem = True
	if not ghc_util_checkWebAdmin(webConfig):
		problem = True
		web_serviceCheck = False
	if not ghc_util_checkMobPortConnectivity(mobilityConfig):
		problem = True
		mobile_serviceCheck = False
	if not ghc_util_checkGWPortConnectivity(gwConfig):
		problem = True
	if not ghc_util_checkWebPortConnectivity(webConfig):
		problem = True
		web_serviceCheck = False
=======
	if not ghc_util_checkGroupWise(gwConfig):
		problem = True
	if not ghc_util_checkMobPortConnectivity(mobilityConfig):
		problem = True
	if not ghc_util_checkGWPortConnectivity(gwConfig):
		problem = True
>>>>>>> origin/Development

	if problem:
		ghc_util_passFail('failed')
	elif not problem:
		ghc_util_passFail('passed')

def ghc_checkLDAP(XMLconfig ,ldapConfig):
	ghc_util_NewHeader("Checking LDAP Connectivity..")
	problem = False

	if ldapConfig['enabled'] != 'true':
		problem = 'skipped'
	elif ldapConfig['enabled'] == 'true':
		if not ds.checkLDAP(XMLconfig ,ldapConfig):
			problem = True

	if problem == 'skipped':
		msg = "LDAP not enabled\n"
		ghc_util_passFail('skipped', msg)
	elif problem:
		msg = "Unable to make LDAP connection\n"
		ghc_util_passFail('failed', msg)
	elif not problem:
		msg = "Successfully connected to LDAP\n"
		ghc_util_passFail('passed', msg)

def ghc_checkRPMs(system_rpms):
	ghc_util_NewHeader("Checking RPMs..")
	problem = False
	ghc_file = dsappConf + '/ghc_RPMs.txt'

	if not os.path.isfile(ghc_file):
		problem = 'warning'
	else:
		# Read in conf/ghc_RPMs.txt
		logger.info("Reading %s" % ghc_file)
		with open(ghc_file, 'r') as open_file:
			required_RPMs = open_file.read().strip().splitlines()

	if problem is not 'warning':
		logger.info("Comparing all system RPMs")
		with open(ghcLog, 'a') as log:
			for rpm in required_RPMs:
				found = False
				for r in system_rpms:
					if rpm in r:
						found = True

				if not found:
					log.write("Missing rpm: %s\n" % rpm)
					problem = True

	if problem == 'warning':
		msg = "No such file %s\n" % ghc_file
		ghc_util_passFail('warning', msg)
	elif problem:
		msg = "\nSuggestion:\nInstall rpm(s) from YaST or with the following command:\nzypper in <packageName>\n"
		ghc_util_passFail('failed', msg)
	elif not problem:
		msg = "All required RPMs found\n"
		ghc_util_passFail('passed', msg)

def ghc_checkProxy():
	ghc_util_NewHeader("Checking Proxy Configuration..")
	problem = False

	if os.path.isfile(proxyConf):
		with open(proxyConf, 'r') as proxyFile:
			proxy_settings = proxyFile.read()
	else:
		logger.debug("No such folder or file: %s" % proxyConf)
		proxy_settings = ''

	# Get no_proxy list
	try:
		noProxy = os.environ['no_proxy']
	except KeyError:
		noProxy = None

	with open(ghcLog, 'a') as log:
		# Check if proxy  is enabled
		if noProxy is not None:
			if 'PROXY_ENABLED="yes"' in proxy_settings:
				log.write("Proxy enabled detected\n\n")
			elif proxy_settings == '':
				log.write("Proxy settings detected\nUnable to validate enabled\n")

			proxy_checks = ['localhost', '127.0.0.1']
			proxy_checks.append(socket.gethostbyname(dsHostname))
			proxy_checks.append(dsHostname)

			for check in proxy_checks:
				if check not in noProxy:
					problem = True
			if len(noProxy.split(',')) <= 4:
				problem = 'warning-1'

		elif 'PROXY_ENABLED="yes"' in proxy_settings and noProxy is None:
			problem = 'warning-2'


	if problem == 'warning-1':
		msg = "Possible missing addresses in 'No_PROXY'\nSee TID 7009730 for proper proxy configuration with Mobility\n"
		ghc_util_passFail('warning', msg)
	elif problem == 'warning-2':
		msg = "Proxy enabled detected\nSystem environment not updated. Please restart server\n"
		ghc_util_passFail('warning', msg)
	elif problem:
		msg = "Invalid configuration of proxy detected\nSee TID 7009730 for proper proxy configuration with Mobility\n"
		ghc_util_passFail('failed', msg)
	elif not problem:
		msg = "No proxy detected\n"
		ghc_util_passFail('passed', msg)

def ghc_checkMemory(dbConfig):
	# Display HealthCheck name to user and create section in logs
	ghc_util_NewHeader("Checking Memory..")
	problem = False
	ghc_file = '/proc/meminfo'

	# Get memory
	if os.path.isfile('/proc/meminfo'):
		meminfo = dict((i.split()[0].rstrip(':'),int(i.split()[1])) for i in open(ghc_file).readlines())
		try:
			mem_MB = meminfo['MemTotal'] / 1024
		except:
			mem_MB = '---'
	else:
		logger.debug("No such folder or file: %s" % ghc_file)
		mem_MB = '---'

	# Get number of devices
	conn = ds.getConn(dbConfig, 'mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select count(*) from devices where devicetype!=''")
	data = cur.fetchall()
	cur.close()
	conn.close()

	for row in data:
		numOfDevices = row['count']

	with open(ghcLog, 'a') as log:
		log.write("Number of devices: %s\n" % numOfDevices)
		log.write("Total Memory: %sMB\n\n" % mem_MB)

		# Check against baseline recommendations
		mem_MB = int(mem_MB)
		numOfDevices = int(numOfDevices)

		if mem_MB == '---':
			problem = 'warning-2'
		elif mem_MB < 3500:
			problem = 'warning'
		elif numOfDevices  >= 300 and mem_MB < 3500:
			problem = 'failed-1'
		elif numOfDevices >= 750 and mem_MB < 7500:
			problem = 'failed-2'

	if problem == 'warning':
		msg = "It is recommended to have at least 4GB of Memory for the Mobility server\nSee Mobility Pack System Requirements in documentation\n"
		ghc_util_passFail('warning', msg)
	elif problem == 'warning-2':
		msg = "Unable to detect total memory\n"
		ghc_util_passFail('warning', msg)
	elif problem == 'failed-1':
		msg = "With more than 300 devices, it is recommended to have at least 4GB of Memory\nSee Mobility Pack System Requirements in documentation\n"
		ghc_util_passFail('failed', msg)
	elif problem == 'failed-2':
		msg = "With more than 750 devices, it is recommended to have at least 8GB of Memory\nA single Mobility server can comfortably support approximately 750 devices\nSee Mobility Pack System Requirements in documentation\n"
		ghc_util_passFail('failed', msg)
	elif not problem:
		msg = "Server meets recommended memory\n"
		ghc_util_passFail('passed', msg)

def ghc_checkRPMSave():
	ghc_util_NewHeader("Checking XML rpmsave..")
	problem = False

	rpmSaves = []
	for dirName, subdirList, fileList in os.walk(dirEtcMobility):
		for fname in fileList:
			if '.rpmsave' in fname:
				rpmSaves.append(dirName + "/" + fname)

	with open(ghcLog, 'a') as log:
		if len(rpmSaves) > 0:
			problem = 'warning'
			log.write("Found rpmsaves:\n")
			for r in rpmSaves:
				log.write(r + '\n')

	if problem == 'warning':
		msg = "\nThis could be a problem\nSuggestion: See TID 7012365\n"
		ghc_util_passFail('warning', msg)
	elif not problem:
		msg = "No rpmsave files found\n"
		ghc_util_passFail('passed', msg)

def ghc_checkReqXMLs():
	ghc_util_NewHeader("Checking Required XMLs..")
	problem = False
	ghc_file = dsappConf + '/ghc_XMLs.txt'

	if not os.path.isfile(ghc_file):
		problem = 'warning'
	else:
		# Read in conf/ghc_RPMs.txt
		with open(ghc_file, 'r') as open_file:
			required_XMLs = open_file.read().strip().splitlines()

	if problem is not 'warning':
		with open(ghcLog, 'a') as log:
			for xml in required_XMLs:
				if not os.path.isfile(xml):
					log.write("Missing XML: %s\n" % xml)
					problem = True

	if problem == 'warning':
		msg = "No such file %s\n" % ghc_file
		ghc_util_passFail('warning', msg)
	elif problem:
		ghc_util_passFail('failed', msg)
	elif not problem:
		msg = "All required XMLs found\n"
		ghc_util_passFail('passed', msg)

def ghc_checkTrustedApp(trustedConfig, gwConfig):
	ghc_util_NewHeader("Checking Trusted Application..")
	problem = False

	results = dsSoap.soap_getUserList(trustedConfig, gwConfig)
	if results is None:
		problem = 'None'
	elif results['status']['code'] != 0:
		if 'Invalid key for trusted application' in results['status']['description']:
			problem = 'bad-key'
		if 'Requested record not found' in results['status']['description']:
			problem = 'no-key'

	if problem == 'bad-key':
		msg = "Invalid key for trusted application\n"
		ghc_util_passFail('failed', msg)
	elif problem == 'no-key':
		msg = "Unable to find trusted application: %s\n" % trustedConfig['name']
		ghc_util_passFail('failed', msg)
	elif problem == 'None':
		msg = "Unable to connect to the GroupWise server\n"
		ghc_util_passFail('failed', msg)
	elif not problem:
		msg = "Trusted Application is valid\n"
		ghc_util_passFail('passed', msg)

def ghc_verifyNightlyMaintenance(config_files, mobilityConfig):
	ghc_util_NewHeader("Checking Nightly Maintenance..")
	problem = False

	results = ds.checkNightlyMaintenance(config_files, mobilityConfig, True)

	with open(ghcLog, 'a') as log:
		log.write(results['output'] + '\n')

	problem = results['result']
	if problem:
		# msg = "Invalid key for trusted application\n"
		ghc_util_passFail('failed')
	elif not problem:
		# msg = "Trusted Application is valid\n"
		ghc_util_passFail('passed')

def ghc_checkUpdateSH(dbConfig):
	ghc_util_NewHeader("Checking Database Schema..")
	problem = False

	with open(version, 'r') as file:
		mobilityVersion = file.read()

	conn = ds.getConn(dbConfig, 'datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select service_version from services")
	data = cur.fetchall()
	cur.close()
	conn.close()

	for row in data:
		try:
			ghc_dbVersion = row['service_version']
		except:
			ghc_dbVersion = None

	with open(ghcLog, 'a') as log:
		if ghc_dbVersion is not None and ghc_dbVersion == mobilityVersion:
			log.write("Schema version: %s" % ghc_dbVersion)
			log.write("Mobility version: %s" % mobilityVersion)
		elif ghc_dbVersion is not None and ghc_dbVersion != mobilityVersion:
			log.write("Schema version: %s" % ghc_dbVersion)
			log.write("Mobility version: %s" % mobilityVersion)
			problem = True
		elif ghc_dbVersion is None:
			problem = 'skipped'
		
	if problem == 'skipped':
		msg = "\n\nUnable to verify service version\n"
		ghc_util_passFail('skipped', msg)
	elif problem:
		msg = "\nVersion mismatch between mobility and schema\nSuggestion: Run %s/update.sh to update the schema\n" % dirOptMobility
		ghc_util_passFail('failed', msg)
	elif not problem:
		ghc_util_passFail('passed')

def ghc_checkXML():
	ghc_util_NewHeader("Checking XMLs..")
	problem = False

	xmlFiles = []
	for dirName, subdirList, fileList in os.walk(dirEtcMobility):
		for fname in fileList:
			if '.xml' in fname:
				xmlFiles.append(dirName + "/" + fname)

	xmllint = "xmllint --noout %s"
	with open(ghcLog, 'a') as log:
		for xml in xmlFiles:
			cmd = xmllint % xml
			out = ghc_util_subprocess(cmd, True)
			if out[1] and not out[0]:
				problem = True
				log.write("Problem found with: %s\n" % xml)

	if problem:
		msg = "\nSuggestion: Run 'xmllint --noout <filename>' for more information\n"
		ghc_util_passFail('failed', msg)
	elif not problem:
		msg = "All found XMLs are valid\n"
		ghc_util_passFail('passed', msg)

def ghc_checkDiskSpace():
	ghc_util_NewHeader("Checking Disk Space..")
	problem = False

	cmd = "df -H"
	out = ghc_util_subprocess(cmd)
	device, size, used, available, percent, mountpoint = out[0].split("\n")[1].split()

	with open(ghcLog, 'a') as log:
		log.write(out[0])
		if int(percent.rstrip('%')) >= 90:
			problem = 'warning'
		elif int(percent.rstrip('%')) >= 100:
			problem = True
	
	if problem == 'warning':
		msg = "\nSystem is low on disk space\n"
		ghc_util_passFail('warning', msg)
	elif problem:
		msg + "\nSystem is out of space\n"
		ghc_util_passFail('failed', msg)
	elif not problem:
		ghc_util_passFail('passed')

def ghc_checkManualMaintenance(dbConfig):
	ghc_util_NewHeader("Checking Database Maintenance..")
	dbMaintTolerance = 180
	problem = False

	conn = ds.getConn(dbConfig, 'datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select date_part('days', now() - last_vacuum) as \"days_ago\" from pg_stat_user_tables")
	datasync_data = cur.fetchall()
	cur.close()
	conn.close()

	conn = ds.getConn(dbConfig, 'mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select date_part('days', now() - last_vacuum) as \"days_ago\" from pg_stat_user_tables")
	mobility_data = cur.fetchall()
	cur.close()
	conn.close()

	cmd_datasync = "PGPASSWORD=%(pass)s psql -U %(user)s datasync -c \"select relname,last_vacuum,date_part('days', now() - last_vacuum) as \"days_ago\" from pg_stat_user_tables;\"" % dbConfig
	cmd_mobility = "PGPASSWORD=%(pass)s psql -U %(user)s mobility -c \"select relname,last_vacuum,date_part('days', now() - last_vacuum) as \"days_ago\" from pg_stat_user_tables;\"" % dbConfig
	with open(ghcLog, 'a') as log:
		p = subprocess.Popen(cmd_datasync, shell=True, stdout=subprocess.PIPE)
		p.wait()
		log.write(p.communicate()[0])
		p = subprocess.Popen(cmd_mobility, shell=True, stdout=subprocess.PIPE)
		p.wait()
		log.write(p.communicate()[0])

	ds_allNone = None
	mo_allNone = None

	for row in datasync_data:
		if (row['days_ago']) > dbMaintTolerance:
			problem = True
		if row['days_ago'] is not None:
			ds_allNone = row['days_ago']

	for row in mobility_data:
		if (row['days_ago']) > dbMaintTolerance:
			problem = True
		if row['days_ago'] is not None:
			mo_allNone = row['days_ago']

	if ds_allNone is None or mo_allNone is None:
		problem = True

	if problem:
		msg = "No manual maintenance in over %s days.\nSuggestion: TID 7009453\n" % dbMaintTolerance
		ghc_util_passFail('failed', msg)
	elif not problem:
		ghc_util_passFail('passed')

def ghc_checkConfig():
	ghc_util_NewHeader("Checking Automatic Startup..")
	problem = False

	cmd1 = "chkconfig | grep -i datasync"
	cmd2 = "chkconfig | grep -i datasync | grep -i off"

	out1 = ghc_util_subprocess(cmd1)
	out2 = ghc_util_subprocess(cmd2)

	with open(ghcLog, 'a') as log:
		log.write(out1[0])

	if out2[0]:
		problem = True

	if problem:
		msg = "\nNot all services are configured for automatic startup\n"
		ghc_util_passFail('failed', msg)
	elif not problem:
		ghc_util_passFail('passed')

def ghc_checkPSQLConfig():
	ghc_util_NewHeader("Checking PSQL Configuration..")
	pghba = "/var/lib/pgsql/data/pg_hba.conf"
	problem = False

	# /var/lib/pgsql/data/postgresql.conf
	searchLines = ["local*.*all*.*postgres*.*ident*.*sameuser",
	"host*.*all*.*postgres*.*127.0.0.1/32*.*ident*.*sameuser",
	"host*.*all*.*postgres*.*::1/128*.*ident*.*sameuser",
	"local*.*datasync*.*all*.*md5",
	"host*.*datasync*.*all*.*127.0.0.1/32*.*md5",
	"host*.*datasync*.*all*.*::1/128*.*md5",
	"local*.*postgres*.*datasync_user*.*md5",
	"host*.*postgres*.*datasync_user*.*127.0.0.1/32*.*md5",
	"host*.*postgres*.*datasync_user*.*::1/128*.*md5",
	"local*.*mobility*.*all*.*md5",
	"host*.*mobility*.*all*.*127.0.0.1/32*.*md5",
	"host*.*mobility*.*all*.*::1/128*.*md5"]

	search = "grep -iw %s %s"

	with open(ghcLog, 'a') as log:
		log.write("File: %s\n" % pghba)

		if os.path.isfile(pghba):
			for line in searchLines:
				cmd = search % (line, pghba)
				out = ghc_util_subprocess(cmd)
				if not out[0]:
					log.write("Missing line: " + line.replace('*.*', ' ') + '\n')
					problem = True
		else:
			problem = 'no-file'

	if problem == 'no-file':
		msg = "No such file: %s\n" % pghba
		ghc_util_passFail('failed', msg)
	elif problem:
		ghc_util_passFail('failed')
	elif not problem:
		msg = "All required lines found\n"
		ghc_util_passFail('passed', msg)

def ghc_checkVMWare():
	ghc_util_NewHeader("Checking VMware-tools..")
	problem = False

	cmd = "lspci | grep VMware"
	out = ghc_util_subprocess(cmd)

	vmwareChecks = ['/etc/init.d/vmware-tools-services', '/etc/init.d/vmware-tools']

	with open(ghcLog, 'a') as log:
		if out[0]:
			log.write("Server is running within a virtualized platform\n")
		else:
			problem = 'skipped'

		for check in vmwareChecks:
			if os.path.isfile(check):
				cmd = "%s status" % check
				out = ghc_util_subprocess(cmd)
				if 'not running' in out[0]:
					problem = 'warning'
					log.write("%s is not running\n" % check)

	if problem == 'skipped':
		msg = "VMware not detected\n"
		ghc_util_passFail('skipped', msg)
	elif problem == 'warning':
		ghc_util_passFail('warning')
	elif not problem:
		msg = "VMware-tools is running\n"
		ghc_util_passFail('passed', msg)

def ghc_checkDiskIO():
	ghc_util_NewHeader("Checking Disk IO..")
	problem = False

	cmd = "hdparm -t `df -P /var | tail -1 | cut -d ' ' -f1`"
	out = ghc_util_subprocess(cmd)

	logger.debug("Disk IO %s MB/sec" % out[0].split(' ')[-1-1])
	if float(out[0].split(' ')[-1-1]) <= 13.33:
		problem = 'warning'

	if problem == 'warning':
		msg = "Disk IO appears to be slow\nSee TID 7009812 - Slow Performance of Mobility during peak hours\n"
		ghc_util_passFail('warning', msg)
	elif not problem:
		msg = "Disk IO meets recommended MB/sec\n"
		ghc_util_passFail('passed', msg)

def ghc_checkUserFDN(dbConfig, XMLconfig ,ldapConfig):
	ghc_util_NewHeader("Checking users FDN..")
	problem = False

	if ds.checkLDAP(XMLconfig ,ldapConfig):
		conn = ds.getConn(dbConfig, 'datasync')
		cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
		cur.execute("select distinct dn from targets where disabled='0'")
		data = cur.fetchall()
		cur.close()
		conn.close()

		if len(data) != 0:
			for row in data:
				if ldapConfig['secure'] == 'false':
					cmd = "/usr/bin/ldapsearch -x -H ldap://%s:%s -D %s -w %s -b '%s' -s base" % (ldapConfig['host'], ldapConfig['port'], ldapConfig['login'], ldapConfig['pass'], row['dn'])
				if ldapConfig['secure'] == 'true':
					cmd = "/usr/bin/ldapsearch -x -H ldaps://%s:%s -D %s -w %s -b '%s' -s base" % (ldapConfig['host'], ldapConfig['port'], ldapConfig['login'], ldapConfig['pass'], row['dn'])

				out = ghc_util_subprocess(cmd, True)

				with open(ghcLog, 'a') as log:
					if 'dn:' not in out[0]:
						log.write("Invalid FDN: %s\n" % row['dn'])
						problem = True
	else:
		problem = 'skipped'

	if problem == 'skipped':
		msg = "LDAP check did not pass\n"
		ghc_util_passFail('skipped', msg)
	elif problem:
		ghc_util_passFail('warning')
	elif not problem:
		msg = "All users LDAP FDNs are valid\n"
		ghc_util_passFail('passed', msg)

def ghc_verifyDatabaseIntegrity(dbConfig):
	ghc_util_NewHeader("Checking Databases Integrity..")
	problem = False

	found = None

	conn = ds.getConn(dbConfig, 'datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select distinct dn from targets where disabled='0' and \"targetType\"='user'")
	ds_data = cur.fetchall()
	cur.close()
	conn.close()

	conn = ds.getConn(dbConfig, 'mobility')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select distinct userid from users")
	mo_data = cur.fetchall()
	cur.close()
	conn.close()


	with open(ghcLog, 'a') as log:
		log_writeNotFound = True
		for ds_row in ds_data:
			found = False
			for mo_row in mo_data:
				if ds_row['dn'] == mo_row['userid']:
					found = True
			if not found:
				if log_writeNotFound:
					log.write("Not found in mobility database:\n")
					log_writeNotFound = False
				log.write("%s\n" % ds_row['dn'])
				problem = True

		log_writeNotFound = True
		for mo_row in mo_data:
			found = False
			for ds_row in ds_data:
				if mo_row['userid'] == ds_row['dn']:
					found = True
			if not found:
				if log_writeNotFound:
					log.write("\nNot found in datasync database:\n")
					log_writeNotFound = False
				log.write("%s\n" % mo_row['userid'])
				problem = True

	if problem:
		ghc_util_passFail('failed')
	elif not problem:
		msg = "All detected users found in both databases\n"
		ghc_util_passFail('passed', msg)

def ghc_verifyTargetsIntegrity(dbConfig):
	ghc_util_NewHeader("Checking Targets Table..")
	problem = False

	conn = ds.getConn(dbConfig, 'datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select dn,\"connectorID\" from targets where disabled='0'")
	data = cur.fetchall()
	cur.close()
	conn.close()

	userRef = dict()
	for row in data:
		if row['dn'] not in userRef:
			userRef[row['dn']] = [1,row['connectorID']]
		else:
			userRef[row['dn']][0] = userRef[row['dn']][0] + 1

	with open(ghcLog, 'a') as log:
		for row in userRef:
			if userRef[row][0] != 2:
				if 'groupwise' in userRef[row][1]:
					log.write("Missing in mobility connector: %s\n" % row)
				elif 'mobility' in userRef[row][1]:
					log.write("Missing in groupwise connector: %s\n" % row)
				problem = True

	if problem:
		ghc_util_passFail('failed')
	elif not problem:
		msg = "All targets on both connectors\n"
		ghc_util_passFail('passed', msg)

def ghc_checkReferenceCount(dbConfig):
	ghc_util_NewHeader("Checking Reference Count..")
	problem = False

	conn = ds.getConn(dbConfig, 'datasync')
	cur = conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
	cur.execute("select distinct \"referenceCount\",dn from targets")
	target_data = cur.fetchall()
	cur.execute("select memberdn,groupdn from \"membershipCache\"")
	member_data = cur.fetchall()
	cur.close()
	conn.close()

	log_newline = False
	with open(ghcLog, 'a') as log:
		for row in target_data:
			if row['referenceCount'] != 1:
				count = 0
				for line in member_data:
					if row['dn'] == line['memberdn']:
						count += 1
				if row['referenceCount'] != count:
					if log_newline:
						log.write('\n')
					log.write("Problem found: %s\nTarget count: %s\nMember count: %s\n" % (row['dn'], row['referenceCount'],count))
					log_newline = True
					problem = True

	if problem:
		ghc_util_passFail('failed')
	elif not problem:
		msg = "All reference counts are correct\n"
		ghc_util_passFail('passed', msg)

<<<<<<< HEAD
def ghc_verifyCertificates(mobilityConfig, webConfig):
	ghc_util_NewHeader("Checking Certificates..")
	problem = False
	global web_serviceCheck
	global mobile_serviceCheck
	global serverDateCheck

	devCert = dirVarMobility + "/device/mobility.pem"
	webCert = dirVarMobility + "/webadmin/server.pem"
	CACert = dirVarMobility + "/common/CA/trustedroot.pem"
	dateTolerance = 7776000

	# Verify cert path
	no_dev = False
	no_web = False
	no_CA = False
	if not os.path.isfile(devCert):
		problem = 'no-file'
		no_dev = True
	if not os.path.isfile(webCert):
		problem = 'no-file'
		no_web = True
	if not os.path.isfile(CACert):
		problem = 'no-file'
		no_CA = True

	if not no_dev and not no_web and not no_CA:
		# Check certificate expiry
		devChk = "openssl x509 -checkend %s -in %s" % (dateTolerance, devCert)
		webChk = "openssl x509 -checkend %s -in %s" % (dateTolerance, webCert)
		CAChk = "openssl x509 -checkend %s -in %s" % (dateTolerance, CACert)
		devOut = ghc_util_subprocess(devChk)
		webOut = ghc_util_subprocess(webChk)
		CAOut = ghc_util_subprocess(CAChk)

		getDate = "openssl x509 -noout -enddate -in %s"
		with open(ghcLog, 'a') as log:
			cmd = getDate % devCert
			out = ghc_util_subprocess(cmd)[0].split('=')[1]
			if 'will expire' in devOut[0]:
				log.write("File: %s\nCertificate has or will expire in 90 days\nExpiry date: %s\n" % (devCert,out))
				problem = 'warning'
			else:
				log.write("File: %s\nExpiry date: %s\n" %(devCert,out))

			cmd = getDate % webCert
			out = ghc_util_subprocess(cmd)[0].split('=')[1]
			if 'will expire' in webOut[0]:
				log.write("File: %s\nCertificate has or will expire in 90 days\nExpiry date: %s\n" % (webCert,out))
				problem = 'warning'
			else:
				log.write("File: %s\nExpiry date: %s\n" %(webCert,out))

			cmd = getDate % CACert
			out = ghc_util_subprocess(cmd)[0].split('=')[1]
			if 'will expire' in CAOut[0]:
				log.write("File: %s\nCertificate has or will expire in 90 days\nExpiry date: %s\n" % (CACert,out))
				problem = 'warning'
			else:
				log.write("File: %s\nExpiry date: %s\n" %(CACert,out))
			if not serverDateCheck:
				log.write("Warning: Server date check failed - Check expiry date")


			# Check key pair devCert
			cmd = "openssl rsa -in %s -pubout" % devCert
			out1 = ghc_util_subprocess(cmd, True)
			cmd = "openssl x509 -in %s -pubkey -noout" % devCert
			out2 = ghc_util_subprocess(cmd, True)

			if out2[1]:
				log.write("Error: Unable to load certificate")
				problem = True
			else:
				if out1[0] != out2[0]:
					log.write("Private key does not match public certificate\nFile: %s" % devCert)
					problem = True

			# Check key pair webCert
			cmd = "openssl rsa -in %s -pubout" % webCert
			out1 = ghc_util_subprocess(cmd, True)
			cmd = "openssl x509 -in %s -pubkey -noout" % webCert
			out2 = ghc_util_subprocess(cmd, True)

			if out2[1]:
				log.write("Error: Unable to load certificate")
				problem = True
			else:
				if out1[0] != out2[0]:
					log.write("Private key does not match public certificate\nFile: %s" % webCert)
					problem = True

			# Check SSL Handshake mobility.pem
			if mobile_serviceCheck and mobile_serviceCheck is not None:
				cmd = "echo 'QUIT' | openssl s_client -connect %s:%s -CAfile %s" % (mobilityConfig['mlistenAddress'], mobilityConfig['mPort'], devCert)
				out = ghc_util_subprocess(cmd,True)
				if 'return code: 0 (ok)' not in out[0]:
					log.write("Handshake Failed: Return code: 0 (ok) not found\nAttempt made to: %s:%s\nCA file: %s\n" % (mobilityConfig['mlistenAddress'], mobilityConfig['mPort'], devCert))
					problem = 'warning'
				else:
					log.write("Handshake Successful\nConnect: %s:%s\nCA File: %s\n" % (mobilityConfig['mlistenAddress'], mobilityConfig['mPort'], devCert))
			else:
				log.write("Problem with mobility connector\nUnable to request handshake with %s:%s\n" % (mobilityConfig['mlistenAddress'], mobilityConfig['mPort']))
				problem = 'warning'
			log.write('\n')

			# Check SSL Handshake server.pem
			if web_serviceCheck and web_serviceCheck is not None:
				cmd = "echo 'QUIT' | openssl s_client -connect %s:%s -CAfile %s" % (webConfig['ip'], webConfig['port'], webCert)
				out = ghc_util_subprocess(cmd,True)
				if 'return code: 0 (ok)' not in out[0]:
					log.write("Handshake Failed: Return code: 0 (ok) not found\nAttempt made to: %s:%s\nCA file: %s\n" % (webConfig['ip'], webConfig['port'], devCert))
					problem = 'warning'
				else:
					log.write("Handshake Successful\nConnect: %s:%s\nCA File: %s\n" % (webConfig['ip'], webConfig['port'], webCert))
			else:
				log.write("Problem with web admin\nUnable to request handshake with %s:%s\n" % (webConfig['ip'], webConfig['port']))
				problem = 'warning'
			# log.write('\n')

			# Check for ^M carriage return character
			cmd = 'grep -Pl "\r" %s %s' % (devCert, webCert)
			out = ghc_util_subprocess(cmd)
			if out[0]:
				problem = True
				log.write("\nFailed: Found ^M carriage return characters\nSuggestion: See TID 7014821\n")

	if problem == 'no-file':
		if no_dev and no_web:
			msg = "Unable to load certificates\nNo such file: %s\nNo such file: %s\n" % (devCert, webCert)
		elif no_dev:
			msg = "Unable to load certificate\nNo such file: %s\n" % devCert
		elif no_web:
			msg = "Unable to load certificate\nNo such file: %s\n" % webCert
		ghc_util_passFail('failed', msg)
	elif problem == 'warning':
		ghc_util_passFail('warning')
	elif problem:
		ghc_util_passFail('failed')
	elif not problem:
		# msg = "No problems found with certificates\n"
		ghc_util_passFail('passed')

def ghc_verifyServerDate():
	ghc_util_NewHeader("Checking Sever Date..")
	problem = False
	global serverDateCheck
	data = []
	c = ntplib.NTPClient()

	Config.read(dsappSettings)
	SERVER = Config.get('GHC', 'ntp.server')

	# Get NTP daytime
	try:
		data = datetime.datetime.utcfromtimestamp(c.request(SERVER, timeout=1).tx_time).strftime('%y %m %d').split(' ')
	except ntplib.NTPException:
		problem = 'bad-ntp'
		logger.error("No response from '%s'" % SERVER)
	except socket.gaierror:
		problem = 'bad-dns'
		logger.error("Name or service not known '%s'" % SERVER)
	except Exception, e:
		problem = True
		logger.error(e)

	if len(data) == 3:
		ntpDate = {'year': int(data[0]), 'month': int(data[1]), 'day': int(data[2])}
	elif len(data) != 3 and not problem:
		problem = 'bad-value'
		logger.error("Could not get year, month, day values from '%s'" % SERVER)

	# Get server daytime
	data = datetime.datetime.utcnow().strftime('%y %m %d').split(' ')
	serverDate = {'year': int(data[0]), 'month': int(data[1]), 'day': int(data[2])}

	# Check drift
	if not problem:
		yearDrift = ntpDate['year'] - serverDate['year']
		monthDrift = ntpDate['month'] - serverDate['month']
		dayDrift = ntpDate['day'] - serverDate['day']

	# Write values to logs
	with open(ghcLog, 'a') as log:
		if not problem:
			log.write("NTP server date: %s\n" % SERVER)
			log.write("Year: %(year)s\nMonth: %(month)s\nDay: %(day)s\n\n" % ntpDate)
		if problem:
			log.write("Failure with NTP server: %s\n\n" % SERVER)
		log.write("Local server date:\n")
		log.write("Year: %(year)s\nMonth: %(month)s\nDay: %(day)s\n" % serverDate)
	if not problem:
		if yearDrift != 0 or monthDrift != 0 or dayDrift != 0:
			problem = True
			log.write("Server time drift detected. Check NTP or local time\n")


	if problem == 'bad-ntp':
		msg = "\nNo response from '%s'\n" % SERVER
		ghc_util_passFail('failed', msg)
	elif problem == 'bad-dns':
		msg = "\nName or service not known '%s'\n" % SERVER
		ghc_util_passFail('failed', msg)
	elif problem == 'bad-value':
		msg = "\nCould not get year, month, day values from '%s'\n" % SERVER
		ghc_util_passFail('failed', msg)
	elif problem:
		serverDateCheck = False
		ghc_util_passFail('failed')
	elif not problem:
		ghc_util_passFail('passed')	
=======
def ghc_verifyCertificates():
	ghc_util_NewHeader("Checking Certificates..")
	problem = True

	devCert = "/var/lib/datasync/device/mobility.pem"
	webCert = "/var/lib/datasync/webadmin/server.pem"
	dateTolerance = 7776000

	devChk = "openssl x509 -checkend %s -in %s" % (dateTolerance, devCert)
	webChk = "openssl x509 -checkend %s -in %s" % (dateTolerance, webCert)
	devOut = ghc_util_subprocess(devChk)
	webOut = ghc_util_subprocess(webChk)

	getDate = "openssl x509 -noout -enddate -in %s"

	with open(ghcLog, 'a') as log:
		cmd = getDate % devCert
		out = ghc_util_subprocess(cmd)[0].split('=')[1]
		if 'will expire' in devOut[0]:
			log.write("File: %s\nCertificate has or will expire in 90 days\nExpiry date: %s\n" % (devCert,out))
			problem = 'warning'
		else:
			log.write("File: %s\nExpiry date: %s\n" %(devCert,out))

		cmd = getDate % webCert
		out = ghc_util_subprocess(cmd)[0].split('=')[1]
		if 'will expire' in webOut[0]:
			log.write("File: %s\nCertificate has or will expire in 90 days\nExpiry date: %s\n" % (webCert,out))
			problem = 'warning'
		else:
			log.write("File: %s\nExpiry date: %s\n" %(devCert,out))

### OLD BASH CODE ### 
# 			# Check Key-Pair
# 			echo -e "\nChecking Certificate-Key Pair:\n------------------------------" >>$ghcLog
# 			diff -qs <(openssl rsa -in $devCert -pubout >>$ghcLog 2>&1) <(openssl x509 -in $devCert -pubkey -noout >>$ghcLog 2>&1) >>$ghcLog 2>&1;
# 			if [ $? -ne 0 ]; then
# 				problem=true
# 				echo "The certificate-key pair are not a match!" >>$ghcLog
# 			fi
# 			echo >>$ghcLog

# 			# Check SSL Handshake
# 			echo | openssl s_client -showcerts -connect $mlistenAddress:$mPort >>$ghcLog 2>&1;
# 			if [ $? -ne 0 ]; then
# 				problem=true
# 			fi

# 		# WebAdmin Certificate
# 		echo -e "\n------------------------------------------------------------\nChecking WebAdmin Certificate:\n------------------------------------------------------------" >>$ghcLog

# 			# Check Expiration Date
# 			echo -e "\nChecking Expiration Date:\n----------------------------" >>$ghcLog
# 			certExpirationDate=`echo | openssl s_client -connect $mlistenAddress:$wPort 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d "=" -f2 | awk '{print $1, $2, $4}'`
# 			if [ $(date -d "$dateTolerance" +%s) -ge $(date -d "$certExpirationDate" +%s) ]; then
# 				echo -e "WARNING: Certificate expires soon!\n$webCert" >>$ghcLog
# 				warn=true;
# 			fi
# 			echo "The WebAdmin certificate will expire on $certExpirationDate" >>$ghcLog

# 			# Check Key-Pair
# 			echo -e "\nChecking Certificate-Key Pair:\n------------------------------" >>$ghcLog
# 			diff -qs <(openssl rsa -in $webCert -pubout >>$ghcLog 2>&1) <(openssl x509 -in $webCert -pubkey -noout >>$ghcLog 2>&1) >>$ghcLog 2>&1;
# 			if [ $? -ne 0 ]; then
# 				problem=true
# 				echo "The certificate-key pair are not a match!" >>$ghcLog
# 			fi
# 			echo >>$ghcLog

# 			# Check SSL Handshake
# 			echo | openssl s_client -showcerts -connect $mlistenAddress:$wPort >>$ghcLog 2>&1;
# 			if [ $? -ne 0 ]; then
# 				problem=true
# 			fi
# 	fi

# 	# Check for dos2unix stuff...
# 	grep -Pl "\r" $devCert $webCert &>/dev/null
# 	if [ $? -eq 0 ]; then
# 		problem=true
# 		echo -e "\nProblem detected with certificates: ^M dos characters.\nSOLUTION: See TID 7014821." >>$ghcLog
# 	fi
>>>>>>> origin/Development
