#!/usr/bin/env python
# Written by Shane Nielson <snielson@projectuminfinitas.com>

__author__ = "Shane Nielson"
__maintainer__ = "Shane Nielson"
__email__ = "snielson@projectuminfinitas.com"


def initVersion():
	global dsappversion
	dsappversion='247'

def initFolders(): # Global Folder variables
	global dsappDirectory
	global dsappConf
	global dsappLogs
	global dsapplib
	global dsappBackup
	global dsapptmp
	global dsappupload
	global dsappdata
	global rootDownloads
	dsappDirectory = "/opt/novell/datasync/tools/dsapp"
	dsappConf = dsappDirectory + "/conf"
	dsappLogs = dsappDirectory + "/logs"
	dsapplib = dsappDirectory + "/lib"
	dsappBackup = dsappDirectory + "/backup"
	dsapptmp = dsappDirectory + "/tmp"
	dsappupload = dsappDirectory + "/upload"
	dsappdata = dsappDirectory + "/data"
	rootDownloads = "/root/Downloads"

def initConfigFiles(): 	# Configuration File
	global config_files
	config_files = dict()
	config_files['mconf'] = "/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml"
	config_files['gconf'] = "/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/groupwise/connector.xml"
	config_files['ceconf'] = "/etc/datasync/configengine/configengine.xml"
	config_files['econf'] = "/etc/datasync/configengine/engines/default/engine.xml"
	config_files['wconf'] = "/etc/datasync/webadmin/server.xml"

def initLogs(): # Set up all used logs
	global configenginelog
	global connectormanagerlog
	global syncenginelog
	global monitorlog
	global systemagentlog
	global updatelog
	global webadminlog
	global statuslog
	global mAlog
	global gAlog
	global mlog
	global glog
	global sudslog
	global log

	log = "/var/log/datasync"
	# Mobility logs
	configenginelog = log + "/configengine/configengine.log"
	connectormanagerlog = log + "/syncengine/connectorManager.log"
	syncenginelog = log + "/syncengine/engine.log"
	monitorlog = log + "/monitorengine/monitor.log"
	systemagentlog = log + "/monitorengine/systemagent.log"
	updatelog = log + "/update.log"
	webadminlog = log + "/webadmin/server.log"
	statuslog = log + "/datasync_status"
	mAlog = None
	gAlog = None
	mlog = None
	glog = None
	sudslog = log + "/connectors/suds.log"

def initSystemLog(): # System logs / settings
	global messagesLog
	global warnLog

	messagesLog = "/var/log/messages"
	warnLog = "/var/log/warn"

def initDsappConfig(): # dsapp Conf / Logs
	global dsappSettings
	global dsappLogSettings
	global dsappLog
	global ghcLog
	global soapDebugLog
	global ghcSettings

	dsappSettings = dsappConf + "/setting.cfg"
	dsappLogSettings = dsappConf + "/logging.cfg"
	dsappLog = dsappLogs + "/dsapp.log"
	ghcLog = dsappLogs + "/generalHealthCheck.log"
	soapDebugLog = dsappLogs + '/soapResults.log'
	ghcSettings = dsappConf + "/ghc_checks.cfg"

def initMiscSettings(): # Misc variables
	global serverinfo
	global initScripts
	global rpminfo
	global dsapp_tar
	global ds_1x
	global ds_2x
	global ds_14x
	global mobilityVersion
	global gmsVersion
	global osVersion
	global python_Directory
	global INIT_NAME
	global OS_VERSION_FILE
	global installedConnector
	global COMPANY_BU
	global DISCLAIMER
	global forceMode

	serverinfo = "/etc/*release"
	initScripts = "/etc/init.d/"
	rpminfo = "datasync"
	dsapp_tar = "dsapp.tgz"
	ds_1x= 1
	ds_2x = 2
	ds_14x = 14
	mobilityVersion = 0
	gmsVersion = "/opt/novell/datasync/version"
	python_Directory = '/usr/bin/python /opt/novell/datasync'
	INIT_NAME = 'datasync-'
	OS_VERSION_FILE = '/etc/issue'
	installedConnector = "/etc/init.d/datasync-connectors"
	COMPANY_BU = 'Micro Focus'
	DISCLAIMER = "%s accepts no liability for the consequences of any actions taken\n     by the use of this application. Use at your own discretion" % COMPANY_BU
	forceMode = False

def initDictonaries():
	global XMLconfig
	global authConfig
	global ldapConfig
	global dbConfig
	global mobilityConfig
	global gwConfig
	global trustedConfig
	global webConfig
	XMLconfig = dict()
	authConfig = dict()
	ldapConfig = dict()
	dbConfig = dict()
	mobilityConfig = dict()
	gwConfig = dict()
	trustedConfig = dict()
	webConfig = dict()

def initMobilityDirectory():
	global dirOptMobility
	global dirEtcMobility
	global dirVarMobility
	global gmsLog
	global dirPGSQL
	global mAttach
	dirOptMobility = "/opt/novell/datasync"
	dirEtcMobility = "/etc/datasync"
	dirVarMobility = "/var/lib/datasync"
	# gmsLog = "/var/log/datasync"
	dirPGSQL = "/var/lib/pgsql"
	mAttach = dirVarMobility + "/mobility/attachments/"