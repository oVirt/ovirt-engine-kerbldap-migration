#!/usr/bin/python
import base64
import glob
import grp
import logging
import os
import pwd
import subprocess
import sys
import tempfile
import uuid


from M2Crypto import RSA


try:
    import dns.resolver
except ImportError:
    raise RuntimeError('Please install python-dns')

try:
    import psycopg2
except ImportError:
    raise RuntimeError('Please install python-psycopg2')

try:
    import argparse
except ImportError:
    raise RuntimeError('Please install python-argparse')

try:
    import ldap
    import ldap.filter
    import ldap.sasl
except ImportError:
    raise RuntimeError('Please install python-ldap')


class Base(object):
    LOG_PREFIX = 'converter'

    @property
    def logger(self):
        return self._logger

    def __init__(self):
        self._logger = logging.getLogger(
            '%s.%s' % (
                self.LOG_PREFIX,
                self.__class__.__name__,
            )
        )


class Statement(Base):

    _connection = None

    def __init__(self):
        super(Statement, self).__init__()

    def connect(
        self,
        host=None,
        port=None,
        secured=False,
        securedHostValidation=True,
        user=None,
        password=None,
        database=None,
    ):
        sslmode = 'allow'
        if secured:
            if securedHostValidation:
                sslmode = 'verify-full'
            else:
                sslmode = 'require'

        self.logger.debug(
            (
                'entry host=%s, port=%s, secured=%s, '
                'securedHostValidation=%s, user=%s, database=%s'
            ),
            host,
            port,
            secured,
            securedHostValidation,
            user,
            database,
        )

        #
        # old psycopg2 does not know how to ignore
        # uselss parameters
        #
        if not host:
            connection = psycopg2.connect(
                database=database,
            )
        else:
            #
            # port cast is required as old psycopg2
            # does not support unicode strings for port.
            # do not cast to int to avoid breaking usock.
            #
            connection = psycopg2.connect(
                host=host,
                port=str(port),
                user=user,
                password=password,
                database=database,
                sslmode=sslmode,
            )

        self._connection = connection

    def execute(
        self,
        statement,
        args=dict(),
    ):
        self.logger.debug('entry statement=%s %s', statement, args)

        ret = []
        cursor = None
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                statement,
                args,
            )
            if cursor.description is not None:
                cols = [d[0] for d in cursor.description]
                while True:
                    entry = cursor.fetchone()
                    if entry is None:
                        break
                    ret.append(dict(zip(cols, entry)))
        finally:
            if cursor is not None:
                cursor.close()

        return ret

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.logger.debug('Commit')
            self._connection.commit()
        else:
            self.logger.debug('Rollback')
            self._connection.rollback()
        self._connection.close()


class OptionDecrypt(Base):

    def __init__(self, prefix='/'):
        super(OptionDecrypt, self).__init__()
        pkcs12 = os.path.join(prefix, 'etc/pki/ovirt-engine/keys/engine.p12')
        password = 'mypass'
        p = subprocess.Popen(
            [
                "openssl",
                "pkcs12",
                "-nocerts", "-nodes",
                "-in", pkcs12,
                "-passin", "pass:%s" % password,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = p.communicate()

        if p.wait() != 0:
            self.logger.debug('openssl stderr: %s', stderr)
            raise RuntimeError('Failed to execute openssl')

        self._rsa = RSA.load_key_string(stdout)

    def decrypt(self, s):
        return self._rsa.private_decrypt(
            base64.b64decode(s),
            padding=RSA.pkcs1_padding,
        )


class VdcOptions(object):

    def __init__(self, statement):
        self._statement = statement

    def _getOptionForDomain(self, domain, name):
        ret = None

        result = self._statement.execute(
            statement="""
                select option_value
                from vdc_options
                where option_name = %(name)s
            """,
            args=dict(
                name=name,
            ),
        )
        if result:
            result = result[0]['option_value']
            for val in result.split(','):
                if val.startswith(domain + ':'):
                    ret = val.split(':', 1)[1]
                    break

        return ret

    def getDomainEntry(self, domain):
        provider = self._getOptionForDomain(domain, 'LDAPProviderTypes')
        if provider == 'activeDirectory':
            provider = 'ad'

        return dict(
            user=self._getOptionForDomain(domain, 'AdUserName'),
            password=self._getOptionForDomain(domain, 'AdUserPassword'),
            provider=provider.lower() if provider else None
        )


class AAADAO(object):

    _legacyAttrs = {
        'active': 'True',
        'group_ids': "''",
        'groups': "''",
        'role': "''",
    }

    def _fetchLegacyAttributes(self):
        for attr in self._legacyAttrs.keys():
            if not self._statement.execute(
                statement="""
                    select 1
                    from pg_class, pg_attribute
                    where
                        pg_attribute.attrelid = pg_class.oid and
                        pg_class.relname = %(table)s and
                        pg_attribute.attname = %(field)s
                """,
                args=dict(
                    table='users',
                    field=attr,
                )
            ):
                del self._legacyAttrs[attr]

    def __init__(self, statement):
        self._statement = statement
        self._fetchLegacyAttributes()

    def isDomainExists(self, new_profile):
        users = self._statement.execute(
            statement="""
                select 1 from users where domain = %(new_profile)s
            """,
            args=dict(
                new_profile=new_profile,
            ),
        )
        groups = self._statement.execute(
            statement="""
                select 1 from ad_groups where domain = %(new_profile)s
            """,
            args=dict(
                new_profile=new_profile,
            ),
        )

        return any([groups, users])

    def fetchLegacyUsers(self, legacy_domain):
        users = self._statement.execute(
            statement="""
                select user_id, username, external_id, last_admin_check_status
                from users
                where domain = %(legacy_domain)s
            """,
            args=dict(
                legacy_domain=legacy_domain,
            ),
        )

        return users

    def fetchLegacyGroups(self, legacy_domain):
        groups = self._statement.execute(
            statement="""
                select id, name, external_id
                from ad_groups
                where domain = %(legacy_domain)s
            """,
            args=dict(
                legacy_domain=legacy_domain,
            ),
        )

        return groups

    def fetchAllPermissions(self):
        return self._statement.execute(
            statement="""select * from permissions""",
        )

    def insertPermission(self, permission):
        self._statement.execute(
            statement="""
                insert into permissions (
                    id,
                    role_id,
                    ad_element_id,
                    object_id,
                    object_type_id
                ) values (
                    %(id)s,
                    %(role_id)s,
                    %(ad_element_id)s,
                    %(object_id)s,
                    %(object_type_id)s
                )
            """,
            args=permission,
        )

    def insertUser(self, user):
        self._statement.execute(
            statement="""
                insert into users (
                    {legacyNames}
                    _create_date,
                    _update_date,
                    department,
                    domain,
                    email,
                    external_id,
                    last_admin_check_status,
                    name,
                    namespace,
                    note,
                    surname,
                    user_id,
                    username
                ) values (
                    {legacyValues}
                    now(),
                    now(),
                    %(department)s,
                    %(domain)s,
                    %(email)s,
                    %(external_id)s,
                    %(last_admin_check_status)s,
                    %(name)s,
                    %(namespace)s,
                    '',
                    %(surname)s,
                    %(user_id)s,
                    %(username)s
                )
            """.format(
                legacyNames='%s%s' % (
                    ','.join(self._legacyAttrs.keys()),
                    '' if not self._legacyAttrs.keys() else ','
                ),
                legacyValues='%s%s' % (
                    ','.join(self._legacyAttrs.values()),
                    '' if not self._legacyAttrs.values() else ','
                )
            ),
            args=user,
        )

    def insertGroup(self, group):
        self._statement.execute(
            statement="""
                insert into ad_groups (
                    distinguishedname,
                    domain,
                    external_id,
                    id,
                    name,
                    namespace
                ) values (
                    '',
                    %(domain)s,
                    %(external_id)s,
                    %(id)s,
                    %(name)s,
                    %(namespace)s
                )
            """,
            args=group,
        )


class Kerberos(Base):

    def __init__(self, prefix):
        super(Kerberos, self).__init__()
        self._prefix = prefix
        self._cache = None
        self._env = None

    def kinit(self, user, password):
        self.logger.debug('kinit')

        fd, self._cache = tempfile.mkstemp()
        os.close(fd)
        self._env = os.environ.get('KRB5CCNAME')
        os.environ['KRB5CCNAME'] = 'FILE:%s' % self._cache

        env = os.environ.copy()
        env['KRB5_CONFIG'] = os.path.join(
            self._prefix,
            'etc/ovirt-engine/krb5.conf',
        )
        p = subprocess.Popen(
            [
                'kinit',
                user,
            ],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = p.communicate(input=password)
        self.logger.debug('kinit stdout=%s, stderr=%s', stdout, stderr)
        if p.wait() != 0:
            raise RuntimeError(
                'Cannot authenticate to kerberos for account %s' % user
            )

    def kdestroy(self):
        self.logger.debug('kdestroy')
        try:
            p = subprocess.Popen(['kdestroy'])
            if p.wait() != 0:
                raise RuntimeError('Failed to execute kdestroy')
        finally:
            if self._env is None:
                del os.environ['KRB5CCNAME']
            else:
                os.environ['KRB5CCNAME'] = self._env
            if self._cache is not None:
                if os.path.exists(self._cache):
                    os.unlink(self._cache)
                self._cache = None


class LDAP(Base):

    _attrUserMap = None
    _attrGroupMap = None
    _bindUser = None
    _bindPassword = None
    _bindSSL = False
    _servers = None

    def __init__(self, kerberos, domain):
        super(LDAP, self).__init__()
        self._kerberos = kerberos
        self._domain = domain

    def _determineNamespace(self, connection=None):
        return None

    def _determineBindUser(self, username, password):
        return username

    def _determineServers(self):
        return [self._domain]

    def _decodeLegacyEntryId(self, id):
        return id

    def _encodeLdapId(self, id):
        return id

    def _getEntryById(self, attrs, entryId):
        ret = None
        result = self.search(
            self.getNamespace(),
            ldap.SCOPE_SUBTREE,
            '(%s=%s)' % (
                attrs['entryId'],
                self._decodeLegacyEntryId(entryId),
            ),
            attrs.values(),
        )
        if result:
            entry = result[0][1]
            ret = {}
            ret['__dn'] = result[0][0]
            for k, v in attrs.items():
                ret[k] = entry.get(v, [''])[0]
            ret['entryId'] = self._encodeLdapId(ret['entryId'])
        return ret

    def getDomain(self):
        return self._domain

    def connect(
        self,
        username,
        password,
        bindDN=None,
        ldapServer=None,
        cacert=None
    ):
        self.logger.debug(
            "Connect uri='%s' user='%s'",
            self._domain,
            username,
        )
        if bindDN is None:
            self._bindUser = self._determineBindUser(username, password)
        else:
            self._bindUser = bindDN
        self._bindPassword = password
        self._bindSSL = cacert is not None
        self._connection = ldap.initialize('ldap://%s' % self._domain)
        self._connection.set_option(ldap.OPT_REFERRALS, 0)
        self._connection.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        if cacert is not None:
            self._connection.set_option(
                ldap.OPT_X_TLS_REQUIRE_CERT,
                ldap.OPT_X_TLS_DEMAND
            )
            # does not work per connection?
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, cacert)
            self._connection.start_tls_s()
        self._connection.simple_bind_s(self._bindUser, password)
        self._namespace = self._determineNamespace()
        self._servers = self._determineServers()

    def search(self, baseDN, scope, filter, attributes, connection=None):
        self.logger.debug(
            "Search baseDN='%s', scope=%s, filter='%s', attributes=%s'",
            baseDN,
            scope,
            filter,
            attributes,
        )
        if connection is None:
            connection = self._connection
        ret = connection.search_s(baseDN, scope, filter, attributes)
        self.logger.debug('SearchResult: %s', ret)
        return ret

    def getNamespace(self):
        return self._namespace

    def getUser(self, entryId):
        user = self._getEntryById(
            attrs=self._attrUserMap,
            entryId=entryId,
        )
        user['user_id'] = str(uuid.uuid4())
        user['external_id'] = user['entryId']
        user['namespace'] = self.getNamespace()
        return user

    def getGroup(self, entryId):
        group = self._getEntryById(
            attrs=self._attrGroupMap,
            entryId=entryId,
        )
        group['id'] = str(uuid.uuid4())
        group['external_id'] = group['entryId']
        group['namespace'] = self.getNamespace()
        return group

    def getUserDN(self):
        return self._bindUser

    def getServers(self):
        return self._servers


class SimpleLDAP(LDAP):

    _simpleNamespaceAttribute = 'defaultNamingContext'
    _simpleProvider = None

    def _determineNamespace(self, connection=None):
        return self.search(
            '',
            ldap.SCOPE_BASE,
            '(objectClass=*)',
            [self._simpleNamespaceAttribute],
            connection=connection,
        )[0][1][self._simpleNamespaceAttribute][0]

    def _determineBindUser(self, username, password):
        try:
            # Note you need cyrus-sasl-gssapi package
            self._kerberos.kinit(username, password)
            connection = ldap.initialize('ldap://%s' % self._domain)
            connection.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
            connection.set_option(ldap.OPT_REFERRALS, 0)
            connection.set_option(ldap.OPT_X_SASL_NOCANON, True)
            connection.sasl_interactive_bind_s(
                '',
                ldap.sasl.sasl(
                    {},
                    'GSSAPI',
                ),
            )
            self._namespace = self._determineNamespace(connection)
            user = self.search(
                self._namespace,
                ldap.SCOPE_SUBTREE,
                '(%s=%s)' % (
                    self._attrUserMap['username'],
                    username.split('@')[0],
                ),
                [self._attrUserMap['entryId']],
                connection=connection,
            )[0][0]

            connection.unbind_s()
            return user
        finally:
            self._kerberos.kdestroy()

    def _determineServers(self):
        servers = [
            srvdata for srvdata in dns.resolver.query(
                '_ldap._tcp.%s' % self._domain,
                'SRV',
            )
        ]
        if not servers:
            return [self._domain]

        sorted(servers, key=lambda server: server.priority, reverse=True)
        return servers

    def getConfig(self):
        return (
            "include = <{provider}.properties>\n"
            "\n"
            "vars.server = {server}\n"
            "vars.user = {user}\n"
            "vars.password = {password}\n"
            "{failovers_variables}\n"
            "\n"
            "pool.default.serverset.single.server = ${{global:vars.server}}\n"
            "{failovers_servers}\n"
            "pool.default.auth.simple.bindDN = ${{global:vars.user}}\n"
            "pool.default.auth.simple.password = ${{global:vars.password}}\n"
            "\n"
            "pool.default.ssl.startTLS = {startTLS}\n"
            "pool.default.ssl.truststore.file = ${{local:_basedir}}/ca.jks\n"
            "pool.default.ssl.truststore.password = changeit"
        ).format(
            provider=self._simpleProvider,
            user=self._bindUser,
            password=self._bindPassword,
            server=self.getServers()[0].target,
            failovers_variables='\n'.join([
                'vars.failover%s = %s' % (
                    i, self.getServers()[i].target
                ) for i in range(1, len(self.getServers()))
            ]),
            failovers_servers='\n'.join([(
                    'pool.default.serverset.failover.server.%s.name'
                    ' = ${global:vars.failover%s}' % (i, i)
                ) for i in range(1, len(self.getServers()))
            ]),
            startTLS='true' if self._bindSSL else 'false',
        )


class RHDSLDAP(SimpleLDAP):

    _simpleProvider = 'rhds'

    _attrUserMap = {
        'entryId': 'nsUniqueId',
        'name': 'givenName',
        'surname': 'sn',
        'email': 'mail',
        'department': 'department',
        'username': 'cn',
    }

    _attrGroupMap = {
        'entryId': 'nsuniqueid',
        'description': 'description',
        'name': 'cn',
    }

    def __init__(self, *args, **kwargs):
        super(RHDSLDAP, self).__init__(*args, **kwargs)

    def _decodeLegacyEntryId(self, id):
        return '%s%s%s-%s' % (id[:13], id[14:23], id[24:28], id[28:])


class OpenLDAP(SimpleLDAP):

    _simpleProvider = 'openldap'

    _attrUserMap = {
        'entryId': 'entryUUID',
        'name': 'givenName',
        'surname': 'sn',
        'email': 'mail',
        'department': 'department',
        'username': 'cn',
    }

    _attrGroupMap = {
        'entryId': 'entryUUID',
        'description': 'description',
        'name': 'cn',
    }

    _simpleNamespaceAttribute = 'namingContexts'

    def __init__(self, *args, **kwargs):
        super(OpenLDAP, self).__init__(*args, **kwargs)


class IPALDAP(SimpleLDAP):

    _simpleProvider = 'ipa'

    _attrUserMap = {
        'entryId': 'ipaUniqueID',
        'name': 'givenName',
        'surname': 'sn',
        'email': 'mail',
        'department': 'department',
        'username': 'cn',
    }

    _attrGroupMap = {
        'entryId': 'ipaUniqueID',
        'description': 'description',
        'name': 'cn',
    }

    def __init__(self, *args, **kwargs):
        super(IPALDAP, self).__init__(*args, **kwargs)


class ADLDAP(LDAP):

    _attrUserMap = {
        'entryId': 'objectGUID',
        'name': 'givenName',
        'surname': 'sn',
        'email': 'mail',
        'department': 'department',
        'username': 'name',
    }

    _attrGroupMap = {
        'entryId': 'objectGUID',
        'description': 'description',
        'name': 'name',
    }

    def _determineBindUser(self, username, password, cacert=None):
        return '%s@%s' % (username.split('@', 1)[0], self._domain)

    def _determineNamespace(self, connection=None):
        _configurationNamingContext = self.search(
            '',
            ldap.SCOPE_BASE,
            '(objectclass=*)',
            ['configurationNamingContext'],
            connection=connection,
        )[0][1]['configurationNamingContext'][0]
        return self.search(
            'CN=Partitions,%s' % _configurationNamingContext,
            ldap.SCOPE_SUBTREE,
            '(&(objectClass=crossRef)(dnsRoot=%s)(nETBIOSName=*))' % (
                self.getDomain(),
            ),
            ['nCName'],
            connection=connection,
        )[0][1]['nCName'][0]

    def __init__(self, *args, **kwargs):
        super(ADLDAP, self).__init__(*args, **kwargs)

    def _decodeLegacyEntryId(self, id):
        return ldap.filter.escape_filter_chars(uuid.UUID(id).bytes_le)

    def _encodeLdapId(self, id):
        return base64.b64encode(id)

    def getConfig(self):
        return (
            "include = <ad.properties>\n"
            "\n"
            "self._vars.domain = {domain}\n"
            "self._vars.user = {user}\n"
            "self._vars.password = {password}\n"
            "\n"
            "pool.default.serverset.type = srvrecord\n"
            "pool.default.serverset.srvrecord.domain = "
            "${{global:vars.domain}}\n"
            "pool.default.auth.simple.bindDN = ${{global:vars.user}}\n"
            "pool.default.auth.simple.password = ${{global:vars.password}}\n"
            "\n"
            "pool.default.ssl.startTLS = {startTLS}\n"
            "pool.default.ssl.truststore.file = ${{local:_basedir}}/ca.jks\n"
            "pool.default.ssl.truststore.password = changeit"
        ).format(
            user=self._bindUser,
            password=self._bindPassword,
            domain=self._domain,
            startTLS='true' if self._bindSSL else 'false',
        )


class AAAProfile(Base):

    _TMP_SUFFIX = '.tmp'

    def __init__(
        self,
        profile,
        authnName,
        authzName,
        driver,
        cacert=None,
        prefix='/',
    ):
        super(AAAProfile, self).__init__()

        extensionsDir = os.path.join(
            prefix,
            'etc/ovirt-engine/extensions.d',
        )
        self._driver = driver
        self._cacert = cacert
        self._vars = dict(
            authnName=authnName,
            authzName=authzName,
            profile=profile,
            configFile=os.path.join('..', 'aaa', '%s.properties' % profile),
        )
        self._files = dict(
            configFile=os.path.join(
                extensionsDir,
                self._vars['configFile']
            ),
            trustStore=os.path.join(
                extensionsDir,
                '..',
                'aaa',
                'ca.jks',
            ),
            authzFile=os.path.join(
                extensionsDir,
                '%s.properties' % authzName
            ),
            authnFile=os.path.join(
                extensionsDir,
                '%s.properties' % authnName
            ),
        )

    def checkExisting(self):
        for f in self._files:
            if os.path.exists(f):
                raise RuntimeError(
                    "File '%s' exists, exiting to avoid damage" % f
                )

    def save(self):
        def _writelog(f, s):
            self.logger.debug("Write '%s'\n%s", f, s)
            f.write(s)

        if not os.path.exists(os.path.dirname(self._files['configFile'])):
            os.makedirs(os.path.dirname(self._files['configFile']))

        if self._cacert is not None:
            from ovirt_engine import java
            p = subprocess.Popen(
                [
                    os.path.join(
                        java.Java().getJavaHome(),
                        'bin',
                        'keytool'
                    ),
                    '-importcert',
                    '-noprompt',
                    '-trustcacerts',
                    '-storetype', 'JKS',
                    '-keystore', '%s%s' % (
                        self._files['trustStore'],
                        self._TMP_SUFFIX,
                    ),
                    '-storepass', 'changeit',
                    '-file', self._cacert,
                    '-alias', 'myca',
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = p.communicate()
            self.logger.debug('keytool stdout: %s, stderr: %s', stdout, stderr)
            if p.wait() != 0:
                raise RuntimeError('Failed to execute keytool')

        with open(
            '%s%s' % (self._files['authzFile'], self._TMP_SUFFIX),
            'w'
        ) as f:
            _writelog(
                f,
                (
                    "ovirt.engine.extension.name = {authzName}\n"

                    "ovirt.engine.extension.bindings.method = "
                    "jbossmodule\n"

                    "ovirt.engine.extension.binding.jbossmodule.module = "
                    "org.ovirt.engine-extensions.aaa.ldap\n"

                    "ovirt.engine.extension.binding.jbossmodule.class = "
                    "org.ovirt.engineextensions.aaa.ldap.AuthzExtension\n"
                    "ovirt.engine.extension.provides = "

                    "org.ovirt.engine.api.extensions.aaa.Authz\n"
                    "config.profile.file.1 = {configFile}\n"
                ).format(**self._vars)
            )
        with open(
            '%s%s' % (self._files['authnFile'], self._TMP_SUFFIX),
            'w'
        ) as f:
            _writelog(
                f,
                (
                    "ovirt.engine.extension.name = {authnName}\n"

                    "ovirt.engine.extension.bindings.method = "
                    "jbossmodule\n"

                    "ovirt.engine.extension.binding.jbossmodule.module = "
                    "org.ovirt.engine-extensions.aaa.ldap\n"

                    "ovirt.engine.extension.binding.jbossmodule.class = "
                    "org.ovirt.engineextensions.aaa.ldap.AuthnExtension\n"

                    "ovirt.engine.extension.provides = "
                    "org.ovirt.engine.api.extensions.aaa.Authn\n"

                    "ovirt.engine.aaa.authn.profile.name = {profile}\n"
                    "ovirt.engine.aaa.authn.authz.plugin = {authzName}\n"
                    "config.profile.file.1 = {configFile}\n"
                ).format(**self._vars)
            )
        with open(
            '%s%s' % (self._files['configFile'], self._TMP_SUFFIX),
            'w'
        ) as f:
            _writelog(f, self._driver.getConfig())

    def __enter__(self):
        self.checkExisting()
        self.oldmask = os.umask(006)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.logger.debug('Commit')
            for f in self._files.values():
                tmp_file = '%s%s' % (f, self._TMP_SUFFIX)
                if os.path.exists(tmp_file):
                    if os.getuid() == 0:
                        uid = pwd.getpwnam('ovirt').pw_uid
                        gid = grp.getgrnam('ovirt').gr_gid
                        os.chown(tmp_file, uid, gid)
                    os.rename(tmp_file, f)

        else:
            self.logger.debug('Rollback')
            for f in self._files.values():
                tmp_file = '%s%s' % (f, self._TMP_SUFFIX)
                if os.path.exists(tmp_file):
                    os.unlink(tmp_file)

        os.umask(self.oldmask)


class RollbackError(RuntimeError):
    pass


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            'Convert legacy users/groups with permissions '
            'into new extension api.'
        ),
    )
    parser.add_argument(
        '--prefix',
        default='/',
        help='for testing withing dev env',
    )
    parser.add_argument(
        '--debug',
        default=False,
        action='store_true',
        help='enable debug log',
    )
    parser.add_argument(
        '--log',
        metavar='FILE',
        default=None,
        help='write log into file',
    )
    parser.add_argument(
        '--cacert',
        metavar='FILE',
        required=True,
        help=(
            'certificate chain to use for ssl, '
            'or "NONE" if you do not want SSL'
        ),
    )
    parser.add_argument(
        '--apply',
        default=False,
        action='store_true',
        help='apply settings'
    )
    parser.add_argument(
        '--domain',
        dest='domain',
        required=True,
        help='domain name to convert',
    )
    parser.add_argument(
        '--authn-name',
        dest='authnName',
        help='authn extension name, default profile name with -authn suffix',
    )
    parser.add_argument(
        '--authz-name',
        dest='authzName',
        help='authz extension name, default profile name with -authz suffix',
    )
    parser.add_argument(
        '--profile',
        dest='profile',
        help='new profile name, default old profile name with -new suffix',
    )
    parser.add_argument(
        '--bind-dn',
        dest='bindDN',
        help='use this DN to bind, instead of kerberos user',
    )
    parser.add_argument(
        '--bind-password',
        dest='bindPassword',
        help='password for ldap bind user',
    )
    parser.add_argument(
        '--ldap-server',
        dest='ldapServer',
        help='use this instead of domain',
    )

    args = parser.parse_args(sys.argv[1:])
    if not args.authnName:
        args.authnName = '%s-authn' % args.domain

    if not args.authzName:
        args.authzName = '%s-authz' % args.domain

    if not args.profile:
        args.profile = '%s-new' % args.domain

    if args.cacert == 'NONE':
        args.cacert = None

    return args


def setupLogger(log=None, debug=False):
    logger = logging.getLogger(Base.LOG_PREFIX)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)

    try:
        h = logging.StreamHandler()
        h.setLevel(logging.INFO)
        h.setFormatter(
            logging.Formatter(
                fmt=(
                    '[%(levelname)-7s] '
                    '%(message)s'
                ),
            ),
        )
        logger.addHandler(h)

        if log is not None:
            h = logging.StreamHandler(open(log, 'w'))
            h.setLevel(logging.DEBUG if debug else logging.INFO)
            h.setFormatter(
                logging.Formatter(
                    fmt=(
                        '%(asctime)-15s '
                        '[%(levelname)-7s] '
                        '%(name)s.%(funcName)s:%(lineno)d '
                        '%(message)s'
                    ),
                ),
            )
            logger.addHandler(h)
    except IOError:
        logging.warning('Cannot initialize logging', exc_info=True)


def convert(args, engineDir):

    DRIVERS = {
        'ad': ADLDAP,
        'ipa': IPALDAP,
        'rhds': RHDSLDAP,
        'openldap': OpenLDAP,
    }

    logger = logging.getLogger(Base.LOG_PREFIX)

    from ovirt_engine import configfile
    engineConfig = configfile.ConfigFile(
        files=[
            os.path.join(
                engineDir,
                'services',
                'ovirt-engine',
                'ovirt-engine.conf',
            ),
            os.path.join(
                args.prefix,
                'etc',
                'ovirt-engine',
                'engine.conf',
            ),
        ],
    )

    statement = Statement()
    logger.info('Connecting to database')
    statement.connect(
        host=engineConfig.get('ENGINE_DB_HOST'),
        port=engineConfig.get('ENGINE_DB_PORT'),
        secured=engineConfig.getboolean('ENGINE_DB_SECURED'),
        securedHostValidation=engineConfig.getboolean(
            'ENGINE_DB_SECURED_VALIDATION'
        ),
        user=engineConfig.get('ENGINE_DB_USER'),
        password=engineConfig.get('ENGINE_DB_PASSWORD'),
        database=engineConfig.get('ENGINE_DB_DATABASE'),
    )

    with statement:
        aaadao = AAADAO(statement)
        if aaadao.isDomainExists(args.authzName):
            raise RuntimeError(
                "User/Group from domain '%s' exists in database" % (
                    args.authzName
                )
            )
        logger.info('Loading options')
        domainEntry = VdcOptions(statement).getDomainEntry(args.domain)
        if not all([domainEntry.values()]):
            raise RuntimeError(
                "Domain '%s' does not exists. Exiting." % args.domain
            )

        domainEntry['password'] = OptionDecrypt(prefix=args.prefix).decrypt(
            domainEntry['password'],
        )

        driver = DRIVERS.get(domainEntry['provider'])
        if driver is None:
            raise RuntimeError(
                "Provider '%s' is not supported" % domainEntry['provider']
            )
        ldapServer = args.domain
        if args.ldapServer:
            ldapServer = args.ldapServer

        driver = driver(Kerberos(args.prefix), ldapServer)

        logger.info(
            "Connecting to ldap '%s' using '%s'",
            ldapServer,
            domainEntry['user'],
        )
        driver.connect(
            domainEntry['user'],
            args.bindPassword if args.bindPassword else domainEntry['password'],
            bindDN=args.bindDN,
            cacert=args.cacert
        )

        with AAAProfile(
            profile=args.profile,
            authnName=args.authnName,
            authzName=args.authzName,
            cacert=args.cacert,
            driver=driver,
            prefix=args.prefix,
        ) as aaaprofile:
            logger.info('Converting users')
            users = {}
            for legacyUser in aaadao.fetchLegacyUsers(args.domain):
                logger.debug("Converting user '%s'", legacyUser['username'])
                e = driver.getUser(entryId=legacyUser['external_id'])
                if e is None:
                    logger.warning(
                        (
                            "User '%s' id '%s' could not be found, "
                            "probably deleted from directory"
                        ),
                        legacyUser['external_id'],
                        legacyUser['username'],
                    )
                else:
                    e.update({
                        'domain': args.authzName,
                        'last_admin_check_status': legacyUser[
                            'last_admin_check_status'
                        ],
                    })
                    users[legacyUser['user_id']] = e

            logger.info('Converting groups')
            groups = {}
            for legacyGroup in aaadao.fetchLegacyGroups(args.domain):
                logger.debug("Converting group '%s'", legacyGroup['name'])
                e = driver.getGroup(entryId=legacyGroup['external_id'])
                if e is None:
                    logger.warning(
                        (
                            "Group '%s' id '%s' could not be found, "
                            "probably deleted from directory"
                        ),
                        legacyGroup['external_id'],
                        legacyGroup['name'],
                    )
                else:
                    e['domain'] = args.authzName
                    groups[legacyGroup['id']] = e

            logger.info('Converting permissions')
            permissions = []
            for perm in aaadao.fetchAllPermissions():
                group = groups.get(perm['ad_element_id'])
                if group is not None:
                    perm['id'] = str(uuid.uuid4())
                    perm['ad_element_id'] = group['id']
                    permissions.append(perm)
                else:
                    user = users.get(perm['ad_element_id'])
                    if user is not None:
                        perm['id'] = str(uuid.uuid4())
                        perm['ad_element_id'] = user['user_id']
                        permissions.append(perm)

            logger.info('Adding new users')
            for user in users.values():
                aaadao.insertUser(user)

            logger.info('Adding new groups')
            for group in groups.values():
                aaadao.insertGroup(group)

            logger.info('Adding new permissions')
            for permission in permissions:
                aaadao.insertPermission(permission)

            logger.info('Creating new extensions configuration')
            aaaprofile.save()

            if not args.apply:
                raise RollbackError('Apply was not specified rolling back')


def main():
    args = parse_args()
    setupLogger(log=args.log, debug=args.debug)
    logger = logging.getLogger(Base.LOG_PREFIX)
    logger.debug('Arguments: %s', args)

    if args.prefix == '/':
        engineDir = os.path.join(
            args.prefix,
            'usr',
            'share',
            'ovirt-engine',
        )
    else:
        sys.path.insert(
            0,
            glob.glob(
                os.path.join(
                    args.prefix,
                    'usr',
                    'lib*',
                    'python*',
                    'site-packages',
                )
            )[0]
        )
        engineDir = os.path.join(
            args.prefix,
            'share',
            'ovirt-engine',
        )

    ret = 1
    try:
        convert(args, engineDir)
        ret = 0
    except RollbackError as e:
        logger.warning('%s', e)
    except Exception as e:
        logger.error('Conversion failed: %s', e)
        logger.debug('Exception', exc_info=True)
    return ret


if __name__ == "__main__":
    sys.exit(main())


# vim: expandtab tabstop=4 shiftwidth=4
