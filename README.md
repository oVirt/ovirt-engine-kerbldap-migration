ovirt-engine-kerbldap-migration
===============================

This project contains two different tools. Each tool is described below.

## Migration tool
Migration tool will search for all users/groups and its permissions of a specified domain and copy those users to be usable within new ldap provider. It easily map old legacy users/groups added via manage-domains command to new ldap provider. It also create needed configuration files.
After running this command and restarting engine service you should be able to use new ldap provider with your earlier added users.

## Authz rename tool
This tool will search within /etc/ovirt-engine/extension.d directory for authz and rename it to new name if authz is found or if new name doesn't already exists in database. Both names are passed as command line arguments.

### Building rpm:
Prepare build:
```
autoreconf -ivf
./configure
make
```
Build rpm:
```
./configure
make dist
rpmbuild -tb <tarball>
```

### Example of use:
Usage of migration tool:
```
$ ovirt-engine-kerbldap-migration-tool --domain myldap.com --cacert my.crt --debug --log /tmp/myldap.log --apply
```
Usage of authz rename tool:
```
ovirt-engine-kerbldap-migration-authz-rename --authz-name=myldap-authz --new-name=yourldap-authz --log=/tmp/rename.log --debug
```

### Troubleshooting:
```
- [ERROR  ] Conversion failed: {'desc': 'Inappropriate authentication'} - Means that you can't connect via simple, ?only? GSSAPI, you have to enable simple bind for your search user
```
