legacy-clone-users
==================

This script will copy users/groups and its permissions from legacy domain into new ovirt extension api.

How to get certificate:
$ echo | openssl s_client -connect myldap.com:ldaps 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > my.crt

Example of use:
$ ./converter.py --domain myldap.com --cacert=my.crt --apply
