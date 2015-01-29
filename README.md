ovirt-engine-kerbldap-migration
===============================

This project contains two different tools. Each tool is described below.

## Migration tool
Migration tool will search for all users/groups and its permissions of a specified domain and copy those users to be usable within new ldap provider. It easily map old legacy users/groups added via manage-domains command to new ldap provider. It also create needed configuration files.
After running this command and restarting engine service you should be able to use new ldap provider with your earlier added users.

### Usage:
```
usage: ovirt-engine-kerbldap-migration-tool [-h] [--version] [--debug]
                                            [--log FILE] [--apply] --domain
                                            DOMAIN --cacert FILE
                                            [--authn-name NAME]
                                            [--authz-name NAME]
                                            [--profile NAME] [--bind-user DN]
                                            [--bind-password PASSWORD]
                                            [--ldap-servers DNS]

Migrate legacy users/groups with permissions into new ldap provider.

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --debug               enable debug log
  --log FILE            write log into file
  --apply               apply settings
  --domain DOMAIN       domain name to convert
  --cacert FILE         certificate chain to use for ssl, or "NONE" if you do
                        not want SSL
  --authn-name NAME     authn extension name, default profile name with -authn
                        suffix
  --authz-name NAME     authz extension name, default profile name with -authz
                        suffix
  --profile NAME        new profile name, default old profile name with -new
                        suffix
  --bind-user DN        use this user to bind, instead of performing
                        autodetection
  --bind-password PASSWORD
                        use this password instead of reusing sasl user's
                        password
  --ldap-servers DNS    specify ldap servers explicitly instead of performing
                        autodetection
```
### Proccess of use:
1) Choose the domain you want to convert.
```
$ engine-manage-domains list
Domain: myldap.com
	User name: searchuser@MYLDAP.COM
Manage Domains completed successfully
```
2)[Optional] We strongly recommend this step. Since, without this step you will be using plain connection to ldap. If you obtain your certificate and setup SSL/TLS on your ldap, then the communication will be encrypted.
```
$ echo | openssl s_client -connect myldap.com:ldaps 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > myldap.crt
```
3) Run migration tool without apply and see everthing is fine. Run with --cacert /path/to/cert if you have SSL/TLS or run with --cacert NONE if don't have SSL/TLS setup.
```
$ ovirt-engine-kerbldap-migration-tool --domain myldap.com --cacert myldap.crt --debug --log /tmp/myldap.log
[INFO   ] Connecting to database
[INFO   ] Sanity checks
[INFO   ] Loading options
[INFO   ] Converting users
[INFO   ] Converting groups
[INFO   ] Converting permissions
[INFO   ] Adding new users
[INFO   ] Adding new groups
[INFO   ] Adding new permissions
[INFO   ] Creating new extensions configuration
[INFO   ] Conversion completed
[INFO   ] Conversion was done using single server. Please refer to ovirt-engine-extension-aaa-ldap documentation if you would like to apply failover or other fallback policy.
[WARNING] Apply parameter was not specified rolling back
```
4) Run migration tool with apply and see everthing is fine.
```
$ ovirt-engine-kerbldap-migration-tool --domain myldap.com --cacert myldap.crt --debug --log /tmp/myldap.log --apply
[INFO   ] Connecting to database
[INFO   ] Sanity checks
[INFO   ] Loading options
[INFO   ] Converting users
[INFO   ] Converting groups
[INFO   ] Converting permissions
[INFO   ] Adding new users
[INFO   ] Adding new groups
[INFO   ] Adding new permissions
[INFO   ] Creating new extensions configuration
[INFO   ] Conversion completed
[INFO   ] Conversion was done using single server. Please refer to ovirt-engine-extension-aaa-ldap documentation if you would like to apply failover or other fallback policy.
```
5) Test new ldap provider. Check /var/log/ovirt-engine/engine.log if there are no error messages.
6) Remove legacy domain.
```
$ rhevm-manage-domains delete --domain=myldap.com --force
Successfully deleted domain myldap.com. Please remove all users and groups of this domain using the Administration portal or the API. oVirt Engine restart is required in order for the changes to take place (service ovirt-engine restart).
Manage Domains completed successfully
```
7) Remove all old users/groups from legacy domain.
8) Use Authz renamte tool if needed. See below for description and usage.

## Authz rename tool
This tool will search within /etc/ovirt-engine/extension.d directory for authz and rename it to new name if authz is found and new name doesn't already exists in database. Both names are passed as command line arguments.

### Usage:
```
usage: ovirt-engine-kerbldap-migration-authz-rename [-h] [--version] [--apply]
                                                    [--debug] [--log FILE]
                                                    --authz-name NAME
                                                    --new-name NAME

Overrired current authz with new authz.

optional arguments:
  -h, --help         show this help message and exit
  --version          show program's version number and exit
  --apply            apply settings
  --debug            enable debug log
  --log FILE         write log into file
  --authz-name NAME  name of authz you want to rename
  --new-name NAME    new name of authz extension
```

## Troubleshooting:
```
[ERROR  ] Conversion failed: {'desc': 'Inappropriate authentication'}
```
* Means that you can't connect via ldap simple, you have to enable simple bind for your search user
