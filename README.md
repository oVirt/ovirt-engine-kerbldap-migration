ovirt-engine-kerbldap-migration
===============================

A package to ease migration from oVirt engine legacy LDAP provider into
the new ovirt-engine-extension-aaa-ldap provider, which is much more
robust, flexible and easy to manage.

This package contains two tools:

* Migration tool
  a tool to duplicate legacy LDAP based profile (domain) into a new
  profile based on the new ldap provider.
  All users, groups and permissions are duplicated into the new
  profile.
  The legacy and the new profiles may be used in parallel during
  migration and test period. Existing profile continues to be fully
  functional, and can be removed when new provider is approved.

* Authz rename
  due to rhbz#1133137, the name of authz may be important, in cases
  that password delegation into VM are used, it is required to rename
  the authz name to the original name.

## Migration sequence

1. Install ovirt-engine-extension-aaa-ldap package.
    ```
    # yum install ovirt-engine-extension-aaa-ldap
    ```

2. Choose the domain you want to convert.
    ```
    # engine-manage-domains list
    Domain: myldap.com
        User name: searchuser@MYLDAP.COM
    Manage Domains completed successfully
    ```

3. [Optional] Obtaining LDAP CA certificate.

    We strongly recommend of using TLS/SSL protocol to communicate with
    LDAP securely. Doing so requires the CA certificate that issued the
    LDAP service certificate.

    If you do not wish to use TLS/SSL specify --cacert NONE in the
    following commands.

  **Active Directory**

    1. Press "Start" -> "Run" and write "cmd" and press "Enter".
    2. Into cmd write "certutil -ca.cert ad.crt"
    3. Copy "ca.crt" to ovirt machine.
  
  **OpenLDAP**

    In your slapd.conf find the value of "TLSCACertificateFile". This value
    is path to your certificate. Copy it to your ovirt machine.
  
  **FreeIPA**

    In IPA you can find root CA at "/etc/ipa/ca.crt", copy it to your ovirt
    machine.

4. Execute migration tool in non destructive mode.
    ```
    # ovirt-engine-kerbldap-migration-tool --domain myldap.com --cacert /tmp/myldap.crt
    <snip>
    [WARNING] Apply parameter was not specified rolling back
    ```

    The migration tool will search for all users, groups and permissions
    of selected domain and will duplicate them into the new domain. It
    will also create the configuration needed to run the new provider.

    Please refer to *ovirt-engine-kerbldap-migration-tool* usage for
    additional options.

    Before proceeding, make sure no error is printed. In case of an error
    please refer to the problem determination section.

5. Execute migration tool and apply settings.
    ```
    # ovirt-engine-kerbldap-migration-tool --domain myldap.com --cacert /tmp/myldap.crt --apply
    <snip>
    [INFO   ] Conversion completed
    <snip>
    ```

6. Restart engine.
    ```
    # service ovirt-engine restart
    or:
    # systemctl restart ovirt-engine
    ```

7. Test drive your new provider

    * Profile name will be *myldap.com*-new.
    * Try to login using your current user names, checkout group assignments.
    * Try to search directory, the authz name will be  *myldap.com*-authz.

8. Remove the legacy provider.
    ```
    # engine-manage-domains delete --domain=myldap.com --force
    Successfully deleted domain myldap.com. Please remove all users and groups of this domain using the Administration portal or the API. oVirt Engine restart is required in order for the changes to take place (service ovirt-engine restart).
    Manage Domains completed successfully
    ```

9. Restart engine.
    ```
    # service ovirt-engine restart
    or:
    # systemctl restart ovirt-engine
    ```

10. Remove all legacy users and groups.

    * Login into WebAdmin.
    * Go to Users tab.
    * Sort by "Authorization provider".
    * Remove all that have "Authorization provider" *myldap.com*.

11. [OPTIONAL] Rename authz to match legacy convention.

    These staps are required only if the VM password delegation feature
    is being used (Aka VM SSO).

    1. Execute authz rename tool in non destructive mode.
        ```
        ovirt-engine-kerbldap-migration-authz-rename --authz-name myldap.com-authz --new-name myldap.com
        <snip>
        [WARNING] Apply parameter was not specified rolling back
        ```

        Please refer to *ovirt-engine-kerbldap-migration-tool* usage for
        additional options.

        Before proceeding, make sure no error is printed. In case of an error
        please refer to the problem determination section.

    2. Execute authz rename tool and apply settings.

        ```
        ovirt-engine-kerbldap-migration-authz-rename --authz-name myldap.com-authz --new-name myldap.com
        <snip>
        [INFO   ] Authz was successfully renamed to myldap.com
        ```

    3. Restart engine.
        ```
        # service ovirt-engine restart
        or:
        # systemctl restart ovirt-engine
        ```

## Troubleshooting:

#### Enabling debug log
Add `--debug and --log=/tmp/debug.log` parameters to commands.

#### Simple bind disabled at LDAP server side
```
[ERROR  ] Conversion failed: {'desc': 'Inappropriate authentication'}
```
You have to enable simple bind for your search user

## Usage

### ovirt-engine-kerbldap-migration-tool
```
usage: ovirt-engine-kerbldap-migration-tool [-h] [--version] [--debug]
                                            [--log FILE] [--apply] --domain
                                            DOMAIN --cacert FILE
                                            [--profile NAME]
                                            [--authn-name NAME]
                                            [--authz-name NAME]
                                            [--bind-user DN]
                                            [--bind-password PASSWORD]
                                            [--ldap-servers DNS]
                                            [--krb5conf FILE]

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
  --profile NAME        new profile name, default domain name with -new suffix
  --authn-name NAME     authn extension name, default profile name with -authn
                        suffix
  --authz-name NAME     authz extension name, default profile name with -authz
                        suffix
  --bind-user DN        use this user to bind, instead of performing
                        autodetection
  --bind-password PASSWORD
                        use this password instead of reusing sasl user's
                        password
  --ldap-servers DNS    specify ldap servers explicitly instead of performing
                        autodetection
  --krb5conf FILE       use this krb5 conf instead of ovirt default krb5 conf
```

### ovirt-engine-kerbldap-migration-authz-rename
```
usage: ovirt-engine-kerbldap-migration-authz-rename [-h] [--version] [--debug]
                                                    [--log FILE] [--apply]
                                                    --authz-name NAME
                                                    --new-name NAME

Overrired current authz with new authz.

optional arguments:
  -h, --help         show this help message and exit
  --version          show program's version number and exit
  --debug            enable debug log
  --log FILE         write log into file
  --apply            apply settings
  --authz-name NAME  name of authz you want to rename
  --new-name NAME    new name of authz extension
```
