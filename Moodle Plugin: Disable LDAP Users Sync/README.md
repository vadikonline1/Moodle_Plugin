# Moodle Plugin: Disable LDAP Users Sync

## Description
This Moodle plugin synchronizes and deactivates users from the Moodle Platform, if they are inactive or their account has been deleted from Active Directory (AD).
The plugin depends on LDAP server (`web_site/moodle/admin/settings.php?section=authsettingldap`).
LDAP configuration values ​​are taken from the plugin `Site administration -> Plugins -> Authentication -> LDAP server`


## License
License: GPLv3

## Installation Instructions
1. Place the plugin in the `local` directory of your Moodle installation.
2. Go to the Moodle plugin administration page and install the plugin.
