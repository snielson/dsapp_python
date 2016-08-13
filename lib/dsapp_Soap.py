#!/usr/bin/env python
# Written by Shane Nielson <snielson@projectuminfinitas.com>
__author__ = "Shane Nielson"
__credits__ = ["Tyler Harris", "Tim Draper"]
__maintainer__ = "Shane Nielson"
__email__ = "snielson@projectuminfinitas.com"

import os, sys
import suds.client
import traceback
import logging, logging.config
import dsapp_Definitions as ds

# Global paths
dsappDirectory = "/opt/novell/datasync/tools/dsapp"
dsappConf = dsappDirectory + "/conf"

WSDL = 'file://%s/wsdl/GW2012/groupwise.wsdl' % os.path.dirname(os.path.realpath(__file__))

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (dsappConf))
logger = logging.getLogger('dsapp_Definitions')
excep_logger = logging.getLogger('exceptions_log')

def my_handler(type, value, tb):
	tmp = traceback.format_exception(type, value, tb)
	logger.error("EXCEPTION: See exception.log")
	excep_logger.error("Uncaught exception:\n%s" % ''.join(tmp).strip())
	print (''.join(tmp).strip())

# Install exception handler
sys.excepthook = my_handler


name_space = {
'SOAP-ENV': 'http://schemas.xmlsoap.org/soap/envelope/',
'gwm': 'http://schemas.novell.com/2005/01/GroupWise/methods',
'gwt': 'http://schemas.novell.com/2005/01/GroupWise/types',
'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
}

HTTPS_STRING = "https://"
HTTP_STRING = "http://"
SOAP_STRING = "/soap"
CONTENT_TYPE = "Content-Type"
TEXT_XML = "text/xml"

logoutRequest = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:ns0="http://schemas.novell.com/2005/01/GroupWise/types" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns2="http://schemas.novell.com/2005/01/GroupWise/methods" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
	<SOAP-ENV:Header/>
		<ns1:Body>
			<ns2:logoutRequest>
				<session xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">%s</session>
			</ns2:logoutRequest>
		</ns1:Body>
	</SOAP-ENV:Envelope>
"""

loginRequest = """<?xml version="1.0" encoding="UTF-8"?>
	<SOAP-ENV:Envelope xmlns:ns0="http://schemas.novell.com/2005/01/GroupWise/types" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns2="http://schemas.novell.com/2005/01/GroupWise/methods" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
		<SOAP-ENV:Header/>
		<SOAP-ENV:Body>
			<ns1:loginRequest>
				<auth xmlns="http://schemas.novell.com/2005/01/GroupWise/methods" xsi:type="ns0:TrustedApplication">
					<ns0:username>%s</ns0:username>
					<ns0:name>%s</ns0:name>
					<ns0:key>%s</ns0:key>
				</auth>
				<language xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">en</language>
				<version xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">1.05</version>
				<application xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">dsapp_service</application>
				<userid xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">true</userid>
			</ns1:loginRequest>
		</SOAP-ENV:Body>
	</SOAP-ENV:Envelope>
"""

getFolderListRequest = """<?xml version="1.0" encoding="UTF-8"?>
	<SOAP-ENV:Envelope xmlns:ns0="http://schemas.novell.com/2005/01/GroupWise/types" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns2="http://schemas.novell.com/2005/01/GroupWise/methods" xmlns:tns="http://schemas.novell.com/2005/01/GroupWise/types" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
		<SOAP-ENV:Header>
			<tns:session>%s</tns:session>
		</SOAP-ENV:Header>
		<SOAP-ENV:Body>
			<ns0:getFolderListRequest>
				<parent xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">folders</parent>
				<view xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">default nodisplay pabName</view>
				<recurse xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">true</recurse>
				<imap xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">true</imap>
				<nntp xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">true</nntp>
			</ns0:getFolderListRequest>
		</SOAP-ENV:Body>
	</SOAP-ENV:Envelope>
"""

def soap_getUserInfo(trustedConfig, gwConfig, userConfig, verifyMobility = False):
	soapAddr = None
	# if verifyMobility is True, only check users found in GMS
	if verifyMobility:
		if userConfig['verify'] == 0 or userConfig['verify'] == None:
			print "%s not configured with Mobility" % userConfig['name']
			return
		else:
			userid = userConfig['name']
	else:
		userid = userConfig['name']

	# Get http or https, and put in order to try (for redirects)
	if gwConfig['sSecure'] == 'https':
		secureOrder = ['https', 'http']
	elif gwConfig['sSecure'] == 'http':
		secureOrder = ['http', 'https']
	else:
		print "Missing value for http(s). Aborting"
		logger.error('Missing value for http(s)')
		return

	logger.info("Starting GroupWise SOAP check on '%s' at %s://%s:%s/soap" % (userid,gwConfig['sSecure'], gwConfig['gListenAddress'], gwConfig['sPort']))
	soap = loginRequest % (userid, trustedConfig['name'], trustedConfig['key'])
	soapClient = suds.client.Client(WSDL, location='%(sSecure)s://%(gListenAddress)s:%(sPort)s/soap' % gwConfig)
	soapAddr = '%(sSecure)s://%(gListenAddress)s:%(sPort)s/soap' % gwConfig
	results = soapClient.service.loginRequest(__inject={'msg': soap})

	# Check for invalid soap name / key
	if  'description' in results['status']:
		if "Directory Services Data missing" in results['status']['description']:
			print "Unable to return results. Directory Services Data missing"
			logger.info("Unable to return results. Directory Services Data missing")
			return

	# Check and fix for redirection / http vs https
	if  'description' in results['status']:
		if "Redirect user" in results['status']['description']:
			logger.debug("SOAP redirection to %s://%s:%s/soap" % (secureOrder[0] ,results['redirectToHost'][0]['ipAddress'], results['redirectToHost'][0]['port']))
			soapClient = suds.client.Client(WSDL, location='%s://%s:%s/soap' % (secureOrder[0], results['redirectToHost'][0]['ipAddress'], results['redirectToHost'][0]['port']))
			soapAddr = '%s://%s:%s/soap' % (secureOrder[0], results['redirectToHost'][0]['ipAddress'], results['redirectToHost'][0]['port'])
		try:
			results = soapClient.service.loginRequest(__inject={'msg': soap})
		except:
			logger.debug("SOAP redirection to %s://%s:%s/soap" % (secureOrder[1] ,results['redirectToHost'][0]['ipAddress'], results['redirectToHost'][0]['port']))
			soapClient = suds.client.Client(WSDL, location='%s://%s:%s/soap' % (secureOrder[1], results['redirectToHost'][0]['ipAddress'], results['redirectToHost'][0]['port']))
			soapAddr = '%s://%s:%s/soap' % (secureOrder[1], results['redirectToHost'][0]['ipAddress'], results['redirectToHost'][0]['port'])
			try:
				results = soapClient.service.loginRequest(__inject={'msg': soap})
			except:
				print "Unable to return results for %s" % userid
				logger.warning('Unable to return results for %s' % userid)
				return

	# Create new userConfig dictionary if status code is 0
	logger.info("Done checking '%s' on GroupWise SOAP" % userid)
	if results['status']['code'] == 0:
		soap_userConfig = {'session': results['session'], 'name': results[1]['name'], 'email': results[1]['email'], 'userid': results[1]['userid'], 'domain': results[1]['domain'], 'postoffice': results[1]['postOffice'], 'fid': results[1]['fid'], 'gwVersion': results['gwVersion'], 'build': results['build'], 'soapAddr': soapAddr}
	elif results['status']['description'] is not None:
		print "Problem with '%s'\n%s" % (userid, results['status']['description'])
		logger.warning("Problem with '%s' - %s" % (userid, results['status']['description']))
		return
	else:
		print "Unable to return results for %s" % userid
		logger.warning('Unable to return results for %s' % userid)
		return
	return soap_userConfig

def soap_getFolderList(trustedConfig, gwConfig, userConfig):
	soap_userConfig = soap_getUserInfo(trustedConfig, gwConfig, userConfig)
	if soap_userConfig == None:
		return

	soap = getFolderListRequest % (soap_userConfig['session'])
	soapClient = suds.client.Client(WSDL, location='%(soapAddr)s' % soap_userConfig)
	results = soapClient.service.getFolderListRequest(__inject={'msg': soap})
	return results

def soap_checkFolderList(trustedConfig, gwConfig, userConfig):
	if userConfig['name'] is None:
		return

	problem = False
	print ("Getting folder list..")
	logger.info("Getting folder list..")
	soap_folderList = soap_getFolderList(trustedConfig, gwConfig, userConfig)
	if soap_folderList == None:
		logger.debug("SOAP folder list is None")
		print; ds.eContinue()
		return

	# Get root folder ID
	if soap_folderList[0][0][0]['sid'] == 1:
		root_id = soap_folderList[0][0][0]['id']
	else:
		for folder in soap_folderList[0][0]:
			if folder['sid'] == 1:
				root_id = folder['id']
				break
			else:
				print "Unable to find the root folder for %s" % userConfig['name']
				logger.warning("Unable to find the root folder for %s" % userConfig['name'])
				return

	print ("Checking %s folder structure..\n" % userConfig['name'])
	logger.info("Checking %s folder structure" % userConfig['name'])
	folder_check = ['Mailbox', 'Calendar', 'Contacts']
	for folder in soap_folderList[0][0]:
		if 'folderType' in folder:
			if folder['folderType'] in folder_check:
				if folder['parent'] != root_id:
					print "Problem with system folder structure\n%s not found under root of mailbox\n" % folder['folderType']
					logger.error("Problem with system folder structure - %s not found under root of mailbox\n" % folder['folderType'])
					problem = True
				else:
					if folder['folderType'] == 'Contacts':
						if check_subContacts(soap_folderList, folder['id']): problem = True
					if folder['folderType'] == 'Calendar':
						if check_subCalendars(soap_folderList, folder['id']): problem = True
	if not problem:
		print "No problems found with GroupWise folder structure"
		logger.info("No problems found with GroupWise folder structure")

	print; ds.eContinue()


def soap_printUser(trustedConfig, gwConfig, userConfig):
	soap_userConfig = soap_getUserInfo(trustedConfig, gwConfig, userConfig)
	if soap_userConfig == None:
		return

	# Remove right whitespace
	for key in soap_userConfig:
		soap_userConfig[key] = soap_userConfig[key].rstrip()

	results = """Host: %(soapAddr)s
Domain: %(domain)s
Post Office: %(postoffice)s
POA version: %(gwVersion)s-%(build)s 

User Name: %(name)s 
User Email: %(email)s 
User GroupWise ID: %(userid)s 
User File ID: %(fid)s """ % soap_userConfig

	print results


def soap_getUserList(trustedConfig, gwConfig, noout='true'):
	params = dict()
	params['name'] = trustedConfig['name']
	params['key'] = trustedConfig['key']
	params['noop'] = noout

	gw_location = "%(sSecure)s://%(gListenAddress)s:%(sPort)s/soap" % gwConfig
	logger.debug("GroupWise address: %s" % gw_location)
	soapClient = suds.client.Client(WSDL, location=gw_location)
	try:
		results = soapClient.service.getUserListRequest(**params)
	except:
		results = None
	return results

def check_subCalendars(folderList, parent_id):
	logger.info("Checking sub calendars..")
	logger.debug("Calendar id = %s" % parent_id)
	problem = False
	for folder in folderList[0][0]:
		folderType = 'None'
		try:
			if 'folderType' in folder:
				folderType = folder['folderType']
			if 'isSystemFolder' not in folder or folder['isSystemFolder'] == 'False':
				if folder['calendarAttribute'] and folderType != 'Proxy':
					if folder['parent'] != parent_id:
						print ("Folder structure problem with calendar: %s" % folder['name'])
						logger.warning("Folder structure problem with calendar: %s" % folder['name'])
						logger.debug("%s parent id = %s" % (folder['name'], folder['parent']))
						problem = True
		except:
			pass

	return problem

def check_subContacts(folderList, parent_id):
	logger.info("Checking sub contacts..")
	logger.debug("Contact id = %s" % parent_id)
	problem = False
	for folder in folderList[0][0]:
		try:
			if 'isSystemFolder' not in folder or folder['isSystemFolder'] == 'False':
				if folder['folderType'] == 'UserContacts':
					if folder['parent'] != parent_id:
						print ("Folder structure problem with address book: %s" % folder['name'])
						logger.warning("Folder structure problem with address book: %s" % folder['name'])
						logger.debug("%s parent id = %s" % (folder['name'], folder['parent']))
						problem = True
		except:
			pass

	return problem

def soap_check_sharedFolders(trustedConfig, gwConfig, userConfig):
	logger.info("Getting folder list..")
	soap_folderList = soap_getFolderList(trustedConfig, gwConfig, userConfig)
	if soap_folderList == None:
		logger.debug("SOAP folder list is None")
		return

	count_sharedTo = 0
	count_sharedBy = 0
	for folder in soap_folderList[0][0]:
		if 'isSharedByMe' in folder:
			count_sharedBy += 1
		if 'isSharedToMe' in folder:
			count_sharedTo += 1
	# myDict = {'isSharedByMe': count_sharedBy, 'isSharedToMe' : count_sharedTo}
	print ("Folders shared by %s: %s\nFolders shared to %s: %s" % (userConfig['name'], count_sharedBy, userConfig['name'], count_sharedTo))

def soap_check_allSharedFolders(trustedConfig, gwConfig, userList):
	print ('Totaling all users shared folders... Please wait\n')
	allUsers = {}
	total_sharedBy = 0
	total_sharedTo = 0
	for user in userList:
		userConfig = {'name': user}
		logger.info("Getting folder list..")
		soap_folderList = soap_getFolderList(trustedConfig, gwConfig, userConfig)
		if soap_folderList == None:
			logger.debug("SOAP folder list is None")
		else:
			count_sharedTo = 0
			count_sharedBy = 0
			for folder in soap_folderList[0][0]:
				if 'isSharedByMe' in folder:
					count_sharedBy += 1
					total_sharedBy += 1
				if 'isSharedToMe' in folder:
					count_sharedTo += 1
					total_sharedTo += 1
			myUserDict = {'isSharedByMe': count_sharedBy, 'isSharedToMe' : count_sharedTo}
			allUsers[user] = myUserDict
	allUsers['totalSharedBy'] = total_sharedBy
	allUsers['totalSharedTo'] = total_sharedTo

	listPrint = '---Users shared folders ---\n\n'
	for key in userList:
		if allUsers[key]['isSharedByMe'] > 0 or allUsers[key]['isSharedToMe'] > 0:
			listPrint += ("Folders shared by %s: %s\nFolders shared to %s: %s\n----------------------------------------\n" % (key, allUsers[key]['isSharedByMe'], key, allUsers[key]['isSharedToMe']))
	listPrint += ("\nTotal folders shared by: %s\nTotal folders shared to: %s" % (allUsers['totalSharedBy'], allUsers['totalSharedTo']))
	return listPrint
	# print ("Total folders shared by: %s\nTotal folders shared to: %s" % (allUsers['totalSharedBy'], allUsers['totalSharedTo']))

# This function is for developement / troubleshooting
def soap_checkFolderListTEST(trustedConfig, gwConfig, userConfig):
	problem = False
	print ("Getting folder list..")
	logger.info("Getting folder list..")
	soap_folderList = soap_getFolderList(trustedConfig, gwConfig, userConfig)
	if soap_folderList == None:
		return

	return soap_folderList

	