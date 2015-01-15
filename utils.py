import base64
import grp
import logging
import os
import pwd
import subprocess
import tempfile
import urlparse
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
                'openssl',
                'pkcs12',
                '-nocerts', '-nodes',
                '-in', pkcs12,
                '-passin', 'pass:%s' % password,
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
        ldapServers = self._getOptionForDomain(domain, 'LdapServers')
        if provider == 'activeDirectory':
            provider = 'ad'

        return dict(
            user=self._getOptionForDomain(domain, 'AdUserName'),
            password=self._getOptionForDomain(domain, 'AdUserPassword'),
            provider=provider.lower() if provider else None,
            ldapServers=ldapServers.split(',') if ldapServers else None,
        )


class DNS(Base):

    def __init__(self):
        super(DNS, self).__init__()

    def resolveSRVRecord(self, domain, protocol, service):
        query = '_%s._%s.%s' % (service, protocol, domain)
        response = dns.resolver.query(query, 'SRV')
        self.logger.debug(
            "Query result for srvrecord '%s': %s",
            query,
            response.response,
        )
        if not response:
            raise RuntimeError("Cannot resolve domain '%s'" % domain)

        ret = [
            entry.target.to_text() for entry in sorted(
                response,
                key=lambda e: e.priority,
                reverse=True,
            )
        ]
        self.logger.debug('Return: %s', ret)
        return ret


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


class LDAP(Base):

    _attrUserMap = None
    _attrGroupMap = None

    _profile = None
    _bindUser = None
    _bindPassword = None
    _bindURI = None
    _cacert = None

    def __init__(self, kerberos, profile):
        super(LDAP, self).__init__()
        self._kerberos = kerberos
        self._profile = profile

    def _determineNamespace(self, connection=None):
        return None

    def _determineBindUser(
        self,
        dnsDomain,
        ldapServers,
        saslUser,
        bindPassword,
    ):
        return saslUser.split('@', 1)[0]

    def _decodeLegacyEntryId(self, id):
        return id

    def _determineBindURI(self, dnsDomain, ldapServers):
        return 'ldap://%s' % (ldapServers[0] if ldapServers else dnsDomain)

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

    def connect(
        self,
        dnsDomain,
        ldapServers,
        saslUser,
        bindPassword,
        bindUser,
        cacert=None
    ):
        self.logger.debug(
            (
                "Entry dnsDomain='%s', ldapServers=%s, saslUser='%s', "
                "bindUser='%s', cacert='%s'"
            ),
            dnsDomain,
            ldapServers,
            saslUser,
            bindUser,
            cacert,
        )
        self._bindUser = (
            bindUser if bindUser
            else self._determineBindUser(
                dnsDomain,
                ldapServers,
                saslUser,
                bindPassword,
            )
        )
        self._bindPassword = bindPassword
        self._cacert = cacert
        self._bindURI = self._determineBindURI(
            dnsDomain,
            ldapServers,
        )

        self.logger.debug(
            "connect uri='%s', cacert='%s', bindUser='%s'",
            self._bindURI,
            self._cacert,
            self._bindUser,
        )
        self._connection = ldap.initialize(self._bindURI)
        self._connection.set_option(ldap.OPT_REFERRALS, 0)
        self._connection.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        if self._cacert:
            self._connection.set_option(
                ldap.OPT_X_TLS_REQUIRE_CERT,
                ldap.OPT_X_TLS_DEMAND
            )
            # does not work per connection?
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, self._cacert)
            self._connection.start_tls_s()
        self._connection.simple_bind_s(self._bindUser, self._bindPassword)
        self._namespace = self._determineNamespace()

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

    def getCACert(self):
        return self._cacert

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

    def _determineBindUser(
        self,
        dnsDomain,
        ldapServers,
        saslUser,
        bindPassword,
    ):
        self._kerberos.kinit(saslUser, bindPassword)
        connection = None
        try:
            connection = ldap.initialize(
                'ldap://%s' % (
                    ldapServers[0] if ldapServers
                    else dnsDomain
                )
            )
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
            entry = self.search(
                self._determineNamespace(connection),
                ldap.SCOPE_SUBTREE,
                '(&%s(%s=%s))' % (
                    self._simpleUserFilter,
                    self._attrUserMap['username'],
                    saslUser.split('@')[0],
                ),
                [self._attrUserMap['entryId']],
                connection=connection,
            )

            if not entry:
                raise RuntimeError(
                    "Cannot resolve user '%s' into DN",
                    saslUser,
                )

            return entry[0][0]
        finally:
            if connection:
                connection.unbind_s()
            self._kerberos.kdestroy()

    def _determineBindURI(self, dnsDomain, ldapServers):
        if ldapServers is None:
            ldapServers = DNS().resolveSRVRecord(
                domain=dnsDomain,
                protocol='tcp',
                service='ldap',
            )
        return 'ldap://%s' % ldapServers[0]

    def getConfig(self):
        return (
            'include = <{provider}.properties>\n'
            '\n'
            'vars.server = {server}\n'
            'vars.user = {user}\n'
            'vars.password = {password}\n'
            '\n'
            'pool.default.serverset.single.server = ${{global:vars.server}}\n'
            'pool.default.auth.simple.bindDN = ${{global:vars.user}}\n'
            'pool.default.auth.simple.password = ${{global:vars.password}}\n'
        ).format(
            provider=self._simpleProvider,
            user=self._bindUser,
            password=self._bindPassword,
            server=urlparse.urlparse(self._bindURI).netloc,
        )


class RHDSLDAP(SimpleLDAP):

    _simpleProvider = 'rhds'

    _attrUserMap = {
        'entryId': 'nsUniqueId',
        'name': 'givenName',
        'surname': 'sn',
        'email': 'mail',
        'department': 'department',
        'username': 'uid',
    }

    _attrGroupMap = {
        'entryId': 'nsuniqueid',
        'description': 'description',
        'name': 'cn',
    }

    _simpleUserFilter = '(objectClass=organizationalPerson)(uid=*)'

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
        'username': 'uid',
    }

    _attrGroupMap = {
        'entryId': 'entryUUID',
        'description': 'description',
        'name': 'cn',
    }

    _simpleNamespaceAttribute = 'namingContexts'
    _simpleUserFilter = '(objectClass=uidObject)(uid=*)'

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
        'username': 'uid',
    }

    _attrGroupMap = {
        'entryId': 'ipaUniqueID',
        'description': 'description',
        'name': 'cn',
    }

    _simpleUserFilter = '(objectClass=person)(ipaUniqueID=*)'

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

    def _determineBindUser(
        self,
        dnsDomain,
        ldapServers,
        saslUser,
        bindPassword,
    ):
        return '%s@%s' % (saslUser.split('@', 1)[0], dnsDomain)

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
                self._profile,
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
            'include = <ad.properties>\n'
            '\n'
            'vars.domain = {domain}\n'
            'vars.user = {user}\n'
            'vars.password = {password}\n'
            '\n'
            'pool.default.serverset.type = srvrecord\n'
            'pool.default.serverset.srvrecord.domain = '
            '${{global:vars.domain}}\n'
            'pool.default.auth.simple.bindDN = ${{global:vars.user}}\n'
            'pool.default.auth.simple.password = ${{global:vars.password}}\n'
        ).format(
            user=self._bindUser,
            password=self._bindPassword,
            domain=urlparse.urlparse(self._bindURI).netloc,
        )


class AAAProfile(Base):

    _TMP_SUFFIX = '.tmp'

    def __init__(
        self,
        profile,
        authnName,
        authzName,
        driver,
        prefix='/',
    ):
        super(AAAProfile, self).__init__()

        extensionsDir = os.path.join(
            prefix,
            'etc/ovirt-engine/extensions.d',
        )
        self._driver = driver
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

        cacert = self._driver.getCACert()
        if cacert:
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
                    '-file', cacert,
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
                    'ovirt.engine.extension.name = {authzName}\n'

                    'ovirt.engine.extension.bindings.method = '
                    'jbossmodule\n'

                    'ovirt.engine.extension.binding.jbossmodule.module = '
                    'org.ovirt.engine-extensions.aaa.ldap\n'

                    'ovirt.engine.extension.binding.jbossmodule.class = '
                    'org.ovirt.engineextensions.aaa.ldap.AuthzExtension\n'
                    'ovirt.engine.extension.provides = '

                    'org.ovirt.engine.api.extensions.aaa.Authz\n'
                    'config.profile.file.1 = {configFile}\n'
                ).format(**self._vars)
            )
        with open(
            '%s%s' % (self._files['authnFile'], self._TMP_SUFFIX),
            'w'
        ) as f:
            _writelog(
                f,
                (
                    'ovirt.engine.extension.name = {authnName}\n'

                    'ovirt.engine.extension.bindings.method = '
                    'jbossmodule\n'

                    'ovirt.engine.extension.binding.jbossmodule.module = '
                    'org.ovirt.engine-extensions.aaa.ldap\n'

                    'ovirt.engine.extension.binding.jbossmodule.class = '
                    'org.ovirt.engineextensions.aaa.ldap.AuthnExtension\n'

                    'ovirt.engine.extension.provides = '
                    'org.ovirt.engine.api.extensions.aaa.Authn\n'

                    'ovirt.engine.aaa.authn.profile.name = {profile}\n'
                    'ovirt.engine.aaa.authn.authz.plugin = {authzName}\n'
                    'config.profile.file.1 = {configFile}\n'
                ).format(**self._vars)
            )
        with open(
            '%s%s' % (self._files['configFile'], self._TMP_SUFFIX),
            'w'
        ) as f:
            os.chmod(f.name, 0o660)
            if os.getuid() == 0:
                os.chown(
                    f.name,
                    pwd.getpwnam('ovirt').pw_uid,
                    grp.getgrnam('ovirt').gr_gid,
                )
            _writelog(
                f,
                (
                    '{common}'

                    '\n'

                    'pool.default.ssl.startTLS = {startTLS}\n'

                    'pool.default.ssl.truststore.file = '
                    '${{local:_basedir}}/ca.jks\n'

                    'pool.default.ssl.truststore.password = changeit\n'
                ).format(
                    common=self._driver.getConfig(),
                    startTLS='true' if cacert else 'false',
                )
            )

    def __enter__(self):
        self.checkExisting()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.logger.debug('Commit')
            for f in self._files.values():
                tmp_file = '%s%s' % (f, self._TMP_SUFFIX)
                if os.path.exists(tmp_file):
                    os.rename(tmp_file, f)

        else:
            self.logger.debug('Rollback')
            for f in self._files.values():
                tmp_file = '%s%s' % (f, self._TMP_SUFFIX)
                if os.path.exists(tmp_file):
                    os.unlink(tmp_file)
