## [247 - Unreleased] - 2017-10-08
### Added
- Added more debug logging
- Created CHANGELOG.md

### Changed
- Removed user to delete multiple users at once
- Regex to use word boundary
- Fatal exits to print error on screen
- Changed SOAP to use latest 2014 wsdl
- Moved all variables over to a global file

### Fixed
- Version in loginRequest. This is now works up to Groupwise 18.0.0
- VMtools health check. Now checks SLES12 services as well
- AttributeError on soap_checkFolderList
- Removed early SOAP logoutRequest. Preventing session string invalid

## [246] 2017-08-21
### Added
- Added more debug logging to updateFDN()
- Created new menu in user issues to remove devices for all or specific users

### Fixed
- Removed extra 'Press enter to continue'
- updateFDN() function // Correctly finds the users, and handles spaces in the path
- changeAppName() to use an exact match of dName
- Changed how mobility PIDs are found

## [245] 2017-02-28
### Changed
- Changed dCleanup() to have a single cmd line for each execute

### Fixed
- Fixed verifyUser functions to properly search with regex
- Fixed dCleanup() to properly search with regex
- Fixed dCleanup() to use uUser
- Fixed folder structure check to back track, and find real parent ID
- Fixed sys.path to use insert, so modules are looked up in dsapp first
- Fixed "No such file or directory: '/opt/novell/datasync/tools/dsapp/tmp/ldapGroupMembership.dsapp'" traceback
- Fixed issue with rpm import on SLES 12

## [244] 2017-01-27
### Added
- Added new -r, --reinit switch to reinit all users via command line
- Added INFO logging to dsapp.log for switches called

### Changed
- Changed debug logs to be more clear on failed results in ghc_checkUserFDN()
- Changed --debugMenu to show in help screen // running dsapp -h or dsapp --help

### Fixed
- Fixed SOAP result logs to handle / ignore encoded characters
- Fixed dsapp autoUpdate to start if failed to get latest version
- Fixed updateDsapp() to continue if file not found
- Fixed createCSRKey() to properly exit if passwords do not match
- Fixed the Mobility updates to check for YaST and attempt to close it
- Fixed empty filename crashing dsapp during URL mobility upgrade
- Fixed checkLDAP() to work with very large results

## [243] 2016-12-15
### Added
- Added line 'Updating Mobility database schema..' to mobility update // Should let users know upgrade is still working
- Added error handling for GroupWise server down during SOAP checks
- Added folderStructure logs when checking users folder structure
- Added SOAP results with debug logging enabled

### Changed
- Changed getLogs() also compresses up any folderStructure logs
- Changed getLogs() also compresses up the soapResults.log
- Changed mobility update to stop if fails // Suggest manual steps
- Changed text output in update
- Changed SOAP redirection logs to INFO

### Fixed
- Fixed user check 'List of GMS users & emails' to compare attributes with LOWER()

## [242] 2016-11-21
### Added
- Added 'Check GroupWise folder structure' can now fix structure via SOAP modifyItemRequest

### Changed
- Changed dsapp update to use python Request module
- Removed extra printed text in create pem option

### Fixed
- Fixed certificate code to handle spaces in file name
- Fixed update via local ISO to handle spaces in folder / file name

## [241] 2016-10-26
### Added
- Added debug logging to dsapp_re
- Added GHC ldapsearch timeout
- Added error check for invalid path input with promptVerifyPath()
- Added function insertXML() to add ne

### Changed
- Changed dsappUpdate() function to allow manual path
- Changed autoUpdate to not worry about file name // Was left over code from bash version
- Changed performance menu option name // should make more sense to users
- Changed wording of debug menu // option 0 from back to quit

### Fixed
- Fixed traceback on certificate pre_signCert() with invalid folder path
- Fixed libpython2.6.so.1 being removed during upgrades
- Fixed traceback on certificate createPEM (missing nopassword.key) if moving from sign to createPEM via prompts
- Fixed spinner to show on the correct line in mCleanup()
- Fixed mobility update to auto trust new keys // zypper switch --gpg-auto-import-keys
- Fixed --config restore option to install with backed up settings properly
- Fixed certificate key / csr creation to allow no passwords on private key
- Fixed sPort attribute to properly split the /soap off

## [240] 2016-09-12
### Added
- Added when checking a users shares, it will print a list of all names + ID of the folders
- Added progress counter when checking all users shares
- Added option in 'GroupWise checks options...' to check a users shared folder and total results
- Added option in 'GroupWise checks options...' to check all users shared folders and total results
- Added option to ignore errors on loginRequest
- Added new performance check // Checks for any device set to manual sync. This can put a load on the mobility server
- Added new soap check // getAddresBookListRequest - This should show the shared address books properly
- Added note to pending event check. Note states events could be valid
- Added newfeature into main load up
- Added debug logs to CheckISO function

### Changed
- Changed order of --debugMenu options
- Changed CheckISO to prompt to continue with ISO // perhaps server isoinfo failed.. lets users bypass regardless
- Changed debug logging for remove user // shows actual sql command now
- Changed upload logs to now show progress of upload

### Fixed
- Fixed 'Check GroupWise folder structure' to ignore proxy calendars // GMS does not sync regardless
- Fixed pydoc encoding // Updated pydoc.py
- Fixed 'd' to return to the main menu after closing psql
- Fixed blank text / no echo that sometimes happens after KeyboardInterrupt (ctrl + c) pressed
- Fixed SOAP traceback if result is NONE // Mainly from SOAP not listening
- Fixed syntax issue with PGPASSWORD if password had unique characters
- Fixed syntax issue with ldapsearch if values had unique characters
- Fixed auto update to properly work with changed filename
- Fixed ghc manual maintenance check for tolerance check

## [239] 2016-08-09
SLES 12 Ready

### Added
- Added SLES version check on startup
- Added getUserListReqest SOAP response to debugMenu
- Added libpython2.6 library for SLES 12 installs
- Added rpm libraries for SLES 12 installs
- Added agent log details of queue for show status
- Added new section to setting.cfg: Upload Logs // Adds option to define number of archived logs to upload
- Added new OS version to MISC in setting.cfg
- Added new Config.has_section to startup // adds new sections + defaults as they

### Changed
- Changed RPM build script to longer pre compile py files
- Changed GHC maintenance to check postgres db mod date // No longer fails if install date less than tolerance
- Changed getLogs now grabs datasync_status log
- Changed getLogs now grabs postgres logs
- Changed getLogs now grabs last 2 archived /var/log/message logs
- Changed list_deviceInfo() to display with pydoc
- Changed list_usersAndEmails to display with pydoc
- Removed the "(beta)" from general health check option

### Fixed
- Fixed ip4_addresses() to try/catch for any keyErrors
- Fixed ghc disk check to specifically check /var partition
- Fixed GHC check RPMs to compare different RPMs based on OS version
- Fixed GHC mobility services check // netcat either 'open' or 'succeeded!'
- Fixed GHC PSQL Configuration // OS check for text difference
- Fixed dumpTable // removed -D switch for newer postgres
- Fixed dumpTable to use --insert instead of default copy
- Fixed CUSO to restart postgres before dropping databases // Should clear up any locked db
- Fixed check_userAuth() to read file in reverse without loading file into memory // Should run faster with this method

## [238] 2016-07-08
### Added
- Added performance query string to check if data is empty after parsing logs
- Added performance.log to getLogs()
- Added new netifaces module to ./lib directory
- Added new ip4_addresses() function to dsapp_Definitions
- Added IP check to general health check. Checks to make sure connector IPs are actual interfaces
- Added single option to just generate self-signed certificates
- Added debug logging for Check GroupWise folder structure to help troubleshoot where the problem folder sits
- Added rpm module to ./lib directory
- Added /setuptools-18.2-py2.6.egg to import module list
- Added error and exit for no such file on 'Generate self-signed certificate'

### Changed
- Changed performance countUsers() to prompt for a CSV file
- Changed performance prompt to include message about logs requiring DEBUG
- Changed performance query string prompt to include 'file' in prompt to avoid confusion on path
- Changed 'Update via URL' to display a dynamic text based on the setting.cfg
- Change certificate menu to be more clear on what the options do
- Removed duplicate sys.path.appends for ./lib directory

### Fixed
- Fixed performance countUsers() to use tempfile module. PIPE locked on large data sets
- Fixed Check GroupWise folder structure to ignore system folders on sub calendars and contacts
- Fixed spin.py to include all stdout in try case (Fix for NoneType)
- Fixed GHC certificate checker to skip / ignore mobility.pem if not secure

## [237] 2016-06-01
### Added
- Added new function to get list of current postgres databases
- Added more logging to mutiple functions
- Added logging to checkLDAP() if issues with ldapConfig key 'secure'
- Added logging to debugMenu for each menu item. Showing which option was ran
- Added new dsapp performance methods
- Added new function to build a list of users from parsed logs
- Added new 'performance...' option under 'Checks

### Changed
- Changed dumpTable() to check if file size is 0
- Changed setXML() to hide cleartext value on passwords / keys
- Changed show_GW_syncEvents() to display with pydoc for long lists
- Changed debugMenu to show variables with pydoc, rather than print

### Fixed
- Fixed view_attach_byUser() to group users together again
- Fixed math in view_users_attach() to display true MB
- Fixed dCleanup() to now also search edata for sourceDN (renamed with GMS 14.2.0)
- Fixed dCleanup() regex search to avoid partial match with single characters
- Fixed exception for selecting "0. Back" when printing list of ISO to update from
- Fixed CUSO to check if database exists before attempting to drop it
- Fixed CUSO from dropping the databases if the SQL file pre-checks fail
- Fixed UnboundLocalError exception in ghc_checkDBSchema() on variable ghc_dbVersion
- Fixed dumpTable() to check if databases exists before attempting to create a SQL dump
- Fixed exception handle for base64 decode padding error
- Fixed UnboundLocalError exception in checkLDAP() on variable cmd
- Fixed 'GW pending events by User (consumerevents)' to properly list the users based on sourceName first, sourceDN

## [236] 2016-05-02
### Added
- Added debug logging for every settings.cfg write
- Added extra debug logging to show_GW_syncEvents()
- Added deviceid to whereDidIComeFromAndWhereAmIGoingOrWhatHappenedToMe() output
- Added debug logging to ghc_checkUserFDN()
- Added verifyUser() to accept multiple IDs. Separated by a comma ','
- Added debug logging for each GHC check
- Added prompt to 'Check Mobility attachments count', as it may take time to complete
- Added new option under Attachments... 'View user attachments'. View all users attachments by name, size, time stamp, and filestoreId
- Added dsapp debug menu. Started with 'dsapp --debugMenu'

### Changed
- Removed eContinue() from --bug switch
- Removed extra psql search in dCleanup()
- Removed userid from view_attach_byUser()
- Changed monitorUser() to accept multiple IDs
- Changed 'Checking users FDN' to 'Checking Users FDN' (fixed case)
- Changed setUserState() to accept multiple IDs
- Changed remove_user() (force) to accept multiple IDs
- Changed timeout to 2 seconds in ghc_verifyServerDate()
- Changed 'View attachments by user' to 'View total attachment size by users'
- Changed 'View total attachment size by users' to display with a paged view (like using linux 'le

### Fixed
- Fixed typo in ghc_verifyServerDate()
- Fixed timeout on ghc_verifyServerDate() for google check
- Fixed show_GW_syncEvents() to also catch <sourceDN>
- Fixed general health check to flush output the stdout (see check name before pass/fail/warning/skip)
- Fixed view_attach_byUser() math. Was doubling the size for each user
- Fixed verifyUser() picking up partial matches from incorrect regex search

## [235] 2016-04-01
### Added
- Added more logging

### Changed
- Changed self signed certs to sign certificates with sha256
- Changed minor print outputs

### Fixed
- Fixed rcDS() to start and stop agents in a specific order to start correctly

## [234] 2016-03-30
### Added
- Added option to hide spinner on mobility start/stop/restart with rcDS()
- Added option to hide prints with rcDS()

### Fixed
- Fixed no 'version' attribute in dsUpdate()
- Fixed --config restore switch to properly start Mobility during the connector setup
- Fixed dsUpdate() to reload variables for any script change (1.x to 2.x)

## [233] 2016-03-24
### Added
- Added logging when shutting down, or starting up the mobility agents
- Added 'Q|q' as a option to go back in menus
- Added new patch to FTF list for GMS 14.2.0
- Added python library 'argparse' to lib directory
- Added basic headers to dsapp python files
- Added '#!/usr/bin/evn python' to dsapp python files
- Added debug logging to 'uncompressIt' function
- Added debug logging to 'file_content' function

### Changed
- Removed keeping track of a dsapp PID. No longer needed with the removal of .pgpass file
- Changed print output for found problems with system folder structure. Now includes 'system' in output
- Changed company name from 'Novell' to 'Micro Focus' in several places
- Change output of --bug

### Fixed
- Fixed getUserPAB to check for NoneType on userConfig['type']
- Fixed most user inputs to cancel function when 'q' is put in for user name
- Fixed hostname check while running in cron (skips prompt to fix)
- Fixed formatting for 'apply ftf' if text wraps
- Fixed 'checkNightlyMaintenance' to check bzip2 or gzip compressed files based on file extension