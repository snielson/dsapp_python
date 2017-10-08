## [247] - 2017-10-08
### Added
- Added more debug logging
- Created CHANGELOG.md

### Changed
- Changed remove user to delete multiple users at once
- Changed regex to use word boundary
- Changed fatal exits to print error on screen
- Changed SOAP to use latest 2014 wsdl

### Fixed
- Fixed version in loginRequest. This is now works up to Groupwise 18.0.0
- Fixed vmtools health check. Now checks SLES12 services as well
- Fixed AttributeError on soap_checkFolderList
- Fixed early SOAP logoutRequest