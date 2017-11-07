#!/usr/bin/env python
# Written by Shane Nielson <snielson@projectuminfinitas.com>
from __future__ import print_function

__author__ = "Shane Nielson"
__credits__ = "Neilpang (github.com/Neilpang/acme.sh)"
__maintainer__ = "Shane Nielson"
__email__ = "snielson@projectuminfinitas.com"

import os
import sys
import re
import shutil
import signal
import traceback
import logging, logging.config
import dsapp_Definitions as ds
import dsapp_global as glb

# Log Settings
logging.config.fileConfig('%s/logging.cfg' % (glb.dsappConf))
logger = logging.getLogger('dsapp_Definitions')
excep_logger = logging.getLogger('exceptions_log')

def my_handler(type, value, tb):
	tmp = traceback.format_exception(type, value, tb)
	logger.error("EXCEPTION: See exception.log")
	excep_logger.error("Uncaught exception:\n%s" % ''.join(tmp).strip())
	print (''.join(tmp).strip())

def preexec_function():
	# Ignore the SIGINT signal by setting the handler to the standard
	# signal handler SIG_IGN.
	signal.signal(signal.SIGINT, signal.SIG_IGN)

# Install exception handler
sys.excepthook = my_handler

class acme:

	def __init__(self):
		self.acmePath = os.path.dirname(os.path.realpath(__file__)) + "/acme.sh/"
		self.acmeScript = self.acmePath + 'acme.sh'
		self.acmeLog = glb.dsappLogs + "/acme.log"
		self.acmeRoot = "/root/.acme.sh/"

		self.DNS = None
		self.certPath = None
		self.sslKey = None
		self.sslFullChain = None
		self.acmeInstalled = False
		self.cronInstalled = False

	def clearDNS(self):
		self.DNS = None

	def setDNS(self):
		pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
		userInput = raw_input("Server DNS: ")
		if userInput:
			isIP = pattern.match(userInput)
			if isIP:
				print ("Input is IP address. Must be DNS")
				logger.error("Input is IP address. Must be DNS")
				return False
			else:
				self.DNS = userInput
				logger.info("Setting DNS to [%s]" % userInput)
				return True

	def is_socatInstalled(self):
		cmd = "which socat >/dev/null 2>&1; echo $?"
		out = ds.util_subprocess(cmd)
		return not bool(int(out[0]))

	def is_acmeInstallsed(self):
		if os.path.isdir(self.acmeRoot) and os.path.isfile(self.acmeRoot + '/acme.sh'):
			self.acmeInstalled = True
		else:
			self.acmeInstalled = False

	def is_cronInstalled(self):
		if os.path.isfile('/etc/cron.d/dsapp_acme'):
			self.cronInstalled = True
		else:
			self.cronInstalled = False

	def getAcmeInstalled(self):
		self.is_acmeInstallsed()
		return self.acmeInstalled

	def getCronInstalled(self):
		self.is_cronInstalled()
		return self.cronInstalled

	def installSocat(self):
		installed = False
		if not self.is_socatInstalled():
			print ("Please install socat first")
			logger.warning("Please install socat first")

			if ds.askYesOrNo("Install socat now"):
				cmd = "zypper --non-interactive install socat"
				out = ds.util_subprocess(cmd)
				logger.debug("Running cmd: %s" % cmd)
				if not self.is_socatInstalled():
					print ('Failed to install socat')
					logger.error('Failed to install socat')
					installed = False
				else:
					print ("socat successfully installed\n")
					logger.info("socat successfully installed")
					installed = True
			else:
				installed = False
		else:
			installed = True

		return installed


	def printScript(self):
		print (self.acmeScript)

	def printDNS(self):
		if self.DNS is not None:
			print (self.DNS)
		else:
			print ("DNS has not been configured")

	def printCertPath(self):
		if self.certPath is not None:
			print (self.certPath)
		else:
			print ("Certificate folder has not been configured")

	def printLogPath():
		print (self.acmeLog)

	def printCertificates(self):
		if self.sslKey is not None or self.sslFullChain is not None:
			print (self.sslKey)
			print (self.sslFullChain)
		else:
			print ("Certificates have not been configured")

	def setCertPath(self):
		if self.DNS is None:
			print ("Server DNS is not configured")
			return
		else:
			self.certPath = "/root/.acme.sh/%s" % self.DNS
			logger.info("CertPath set")

	def setCertificates(self):
		if self.certPath is None:
			print ("Certificate path is not configured")
			return
		else:
			self.sslKey = "%s.key" % self.DNS
			self.sslFullChain = "fullchain.cer"
			logger.info("Certificates set")

	def setupAcme(self):
		if ds.askYesOrNo("Install ache.sh onto server"):
			cmd = "%s --install --nocron --debug --no-color --log %s" % (self.acmeScript, self.acmeLog)
			out = ds.util_subprocess(cmd, True)
			logger.debug("Running cmd: %s" % cmd)
			if 'Installed' in out[0]:
				print ("acme.sh successfully installed")
				logger.info("acme.sh successfully installed")
			if 'Install failed' in out[1]:
				print ("ache.sh failed to install. See %s" % self.acmeLog)

	def removeAcme(self):
		print ("This will also remove any cron setup")
		if ds.askYesOrNo("Remove ache.sh from server"):
			cmd = "%s --uninstall --debug --no-color --log %s" % (self.acmeScript, self.acmeLog)
			out = ds.util_subprocess(cmd, True)
			logger.debug("Running cmd: %s" % cmd)
			ds.removeAllFolders(self.acmeRoot)
			ds.removeAllFiles(self.acmeRoot)
			if os.path.isfile("/etc/cron.d/dsapp_acme"):
				logger.info("Removing cron file")
				os.remove("/etc/cron.d/dsapp_acme")
			print ("Uninstall complete")
			logger.info("Uninstall complete")

	def issueCertificate(self, forced=False):
		if not self.installSocat():
			return

		success = False
		if self.DNS is None:
			if not self.setDNS():
				return

		if forced:
			cmd = "%s --issue -d %s --debug --tls --tlsport %s --force --no-color --log %s" % (self.acmeScript, self.DNS, glb.mobilityConfig['mPort'], self.acmeLog)
		else:
			cmd = "%s --issue -d %s --debug --tls --tlsport %s --no-color --log %s" % (self.acmeScript, self.DNS, glb.mobilityConfig['mPort'], self.acmeLog)
		out = ds.util_subprocess(cmd, True)
		logger.debug("Running cmd: %s" % cmd)
		for line in out[1].splitlines():
			if 'on_issue_success' in line.lower():
				success = True

		if not success:
			print ("\nFailed to setup LetsEncrypt certificate")
			logger.error("Failed to setup LetsEncrypt certificate")

		return success

	def checkCertificateConfig(self):
		status = True
		if self.certPath is None:
			print ("Certificate path is not configured")
			logger.error("Certificate path is not configured")
			status = False
		if not os.path.isdir(self.certPath):
			print ("Unable to find certificate folder: %s" % self.certPath)
			logger.error("Unable to find certificate folder: %s" % self.certPath)
			status = False
		if self.sslKey is None or self.sslFullChain is None:
			print ("Certificates have not been configured")
			logger.error("Certificates have not been configured")
			status = False
		if not os.path.isfile(self.certPath + "/" + self.sslKey):
			print ("Unable to find private key: %s" % self.sslKey)
			logger.error("Unable to find private key: %s" % self.sslKey)
			status = False
		if not os.path.isfile(self.certPath + "/" + self.sslFullChain):
			print ("Unable to find certificates: %s" % self.sslFullChain)
			logger.error("Unable to find certificates: %s" % self.sslFullChain)
			status = False

		return status

	def createPem(self):
		if not self.checkCertificateConfig():
			print ("Unable to create pem")
			logger.error("Unable to create pem")
			return

		with open("%s/mobility.pem" % self.certPath, 'w') as pemFile:
			with open("%s/%s" % (self.certPath, self.sslKey), 'r') as privateKey:
				pemFile.write(privateKey.read())
			with open("%s/%s" % (self.certPath, self.sslFullChain), 'r') as fullchain:
				pemFile.write(fullchain.read())

		print ("mobility.pem created at %s/" % self.certPath)

	def autoIssue(self, forced=False):
		# Make sure socat is installed
		if not self.installSocat():
			return

		# Make sure acme root is setup
		if not os.path.isdir(self.acmeRoot):
			print ("acme.sh is not installed. Please install")
			logger.error("acme.sh is not installed. Please install")
			return
		if not os.path.isfile(self.acmeRoot + '/acme.sh'):
			print ("Unable to find %s" % (self.acmeRoot + 'acme.sh'))
			print ("Reinstall acme.sh")
			logger.error("Unable to find %s" % (self.acmeRoot + 'acme.sh'))
			logger.error("Reinstall acme.sh")
			return

		if not int(glb.mobilityConfig['mSecure']):
			print ("Unable to auto issue LetsEncrypt on unsecure connection using port %s" % glb.mobilityConfig['mPort'])
			return

		print ("This will shutdown mobility to free up port %s" % glb.mobilityConfig['mPort'])
		if not ds.askYesOrNo("Start auto LetsEncrypt now"):
			return

		ds.rcDS('stop') # Stop mobility to clear TLS port
		self.setDNS()
		print ("Requesting new certificate from LetsEncrypt with DNS: %s" % self.DNS)
		if self.issueCertificate(forced):
			self.setCertPath()
			self.setCertificates()
			self.createPem()
			ds.configureMobilityCerts(self.certPath, prompts=False)
		else:
			print ("Problem requesting certificate")
			print ("See %s" % self.acmeLog)

		ds.rcDS('start')

	def setAutoRenew(self):
		cronFile = "/etc/cron.d/dsapp_acme"
		cronFormat = "0 %s * * %s /root/.acme.sh/auto-renew.sh %s %s %s >/dev/null 2>&1"
		print ("Auto renew will shutdown mobility if certificate need to update")
		if not ds.askYesOrNo("Set up auto renew now"):
			return

		# Make sure acme root is setup
		if not os.path.isdir(self.acmeRoot):
			print ("acme.sh is not installed. Please install")
			logger.error("acme.sh is not installed. Please install")
			return
		if not os.path.isfile(self.acmeRoot + '/acme.sh'):
			print ("Unable to find %s" % (self.acmeRoot + 'acme.sh'))
			print ("Reinstall acme.sh")
			logger.error("Unable to find %s" % (self.acmeRoot + 'acme.sh'))
			logger.error("Reinstall acme.sh")
			return

		if self.DNS is None:
			self.setDNS()

		day = self.getDay()
		# Get hour from 0-23 for when crontab should run (will restart mobility if needed)
		hour = raw_input("\nHour to check certificates (0-23): ")
		if hour == "" or not 0 <= int(hour) <= 23:
			print ("Invalid hour %s" % hour)
			logger.error("Invalid hour %s" % hour)
			return

		# # Get date to rewnew
		# defaultrenewDate = 20
		# renewDate = raw_input ("Day tolerance for renew (below 60) [%s]: " % defaultrenewDate)
		# if renewDate == "":
		# 	renewDate = defaultrenewDate

		# default to 14 days
		renewDate = 20

		# if not renewDate >= 1 or not renewDate <= 59:
		if not 1 <= int(renewDate) <= 59:
			print ("Invalid tolerance")
			logger.error("Invalid tolerance")
			return

		# Copy auto-renew.sh into place
		print ("\nCopying %s to %s" % (glb.dsapplib + "/scripts/auto-renew.sh", self.acmeRoot))
		logger.info("Copying %s to %s" % (glb.dsapplib + "/scripts/auto-renew.sh", self.acmeRoot))
		shutil.copy(glb.dsapplib + "/scripts/auto-renew.sh", self.acmeRoot)

		# Write new cron.d file
		cron = cronFormat % (hour, day, self.DNS, renewDate, glb.mobilityConfig['mPort'])
		logger.info("Cron will run at [0 %s * * %s]" % (hour, day))
		print ("Creating new cron file at %s" % cronFile)
		logger.info("Creating new file at %s" % cronFile)
		logger.debug("Writing to file: %s" % cron)
		with open(cronFile, 'w') as newCron:
			newCron.write(cron)

	def uninstallAutoRenew(self):
		removed = False
		if os.path.isfile("/etc/cron.d/dsapp_acme"):
			print ("Removing dsapp_acme cron file")
			logger.info("Removing cron file")
			os.remove("/etc/cron.d/dsapp_acme")
			removed = True
		if os.path.isfile("/root/.acme.sh/auto-renew.sh"):
			print ("Removing auto-renew.sh")
			logger.info("Removing auto-renew.sh")
			os.remove("/root/.acme.sh/auto-renew.sh")
			removed = True
		if not removed:
			print ("Nothing to remove")

	def getDay(self):
		# Build list and prompt
		space="   "
		days = ['%sMonday' % space, '%sTuesday' % space, '%sWednesday' % space, '%sThursday' % space, '%sFriday' % space, '%sSaturday' % space, '%sSunday' % space]
		day = None
		available = ds.build_avaiable(days, startWith=1)
		choice = None

		# print list
		print ("\nDay to run certificiate check:\n")
		for x in range(len(days)):
			print ("%s%s.%s" % (space, x + 1, days[x]))

		choice = ds.get_choice(available, no_exit=True, selectionSpace="")
		logger.debug("Selected choice: %s" % choice)
		
		if choice == 1:
			day = 'MON'
		elif choice == 2:
			day = 'TUE'
		elif choice == 3:
			day = 'WED'
		elif choice == 4:
			day = 'THU'
		elif choice == 5:
			day = 'FRI'
		elif choice == 6:
			day = 'SAT'
		elif choice == 7:
			day = 'SUN'

		return day