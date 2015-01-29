# Note you need cyrus-sasl-gssapi package
import base64
import grp
import logging
import os
import pwd
import subprocess
import sys
import urlparse
import uuid


try:
    import ldap
    import ldap.filter
    import ldap.sasl
except ImportError:
    raise RuntimeError('Please install python-ldap')


try:
    import argparse
except ImportError:
    raise RuntimeError('Please install python-argparse')


from ..common import config
from ..common import utils


class AAADAO(utils.Base):

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

    def isAuthzExists(self, authz):
        return self._statement.execute(
            statement="""
                select 1
                from users
                where domain = %(authz)s
                union
                select 1
                from ad_groups
                where domain = %(authz)s
            """,
            args=dict(
                authz=authz,
            ),
        ) == 0

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


class LDAP(utils.Base):

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
            ldapServers = utils.DNS().resolveSRVRecord(
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


class AAAProfile(utils.Base):

    def __init__(
        self,
        profile,
        authnName,
        authzName,
        driver,
        filetransaction,
        prefix='/',
    ):
        super(AAAProfile, self).__init__()

        extensionsDir = os.path.join(
            prefix,
            'etc/ovirt-engine/extensions.d',
        )
        self._driver = driver
        self._filetransaction = filetransaction
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
            self._filetransaction.getFileName(
                self._files['authzFile'],
                forceNew=True,
            ),
            'w',
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
            self._filetransaction.getFileName(
                self._files['authnFile'],
                forceNew=True,
            ),
            'w',
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
            self._filetransaction.getFileName(
                self._files['configFile'],
                forceNew=True
            ),
            'w',
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
        super(AAAProfile, self).__exit__(exc_type, exc_value, traceback)


class RollbackError(RuntimeError):
    pass


def parse_args():
    parser = argparse.ArgumentParser(
        prog='%s-tool' % config.PACKAGE_NAME,
        description=(
            'Migrate legacy users/groups with permissions '
            'into new ldap provider.'
        ),
    )
    parser.add_argument(
        '--version',
        action='version',
        version='%s-%s (%s)' % (
            config.PACKAGE_NAME,
            config.PACKAGE_VERSION,
            config.LOCAL_VERSION
        ),
    )
    parser.add_argument(
        '--prefix',
        default='/',
        help=argparse.SUPPRESS,
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
        '--cacert',
        metavar='FILE',
        required=True,
        help=(
            'certificate chain to use for ssl, '
            'or "NONE" if you do not want SSL'
        ),
    )
    parser.add_argument(
        '--authn-name',
        dest='authnName',
        metavar='NAME',
        help='authn extension name, default profile name with -authn suffix',
    )
    parser.add_argument(
        '--authz-name',
        dest='authzName',
        metavar='NAME',
        help='authz extension name, default profile name with -authz suffix',
    )
    parser.add_argument(
        '--profile',
        dest='profile',
        metavar='NAME',
        help='new profile name, default old profile name with -new suffix',
    )
    parser.add_argument(
        '--bind-user',
        dest='bindUser',
        metavar='DN',
        help='use this user to bind, instead of performing autodetection',
    )
    parser.add_argument(
        '--bind-password',
        dest='bindPassword',
        metavar='PASSWORD',
        help="use this password instead of reusing sasl user's password",
    )
    parser.add_argument(
        '--ldap-servers',
        dest='ldapServers',
        metavar='DNS',
        help=(
            'specify ldap servers explicitly instead of performing  '
            'autodetection'
        ),
    )

    args = parser.parse_args(sys.argv[1:])

    if args.domain == args.profile:
        raise RuntimeError(
            'Profile cannot be the same as domain',
        )

    if not args.authnName:
        args.authnName = '%s-authn' % args.domain

    if not args.authzName:
        args.authzName = '%s-authz' % args.domain

    if not args.profile:
        args.profile = '%s-new' % args.domain

    if args.cacert == 'NONE':
        args.cacert = None

    return args


def convert(args, engine):

    DRIVERS = {
        'ad': ADLDAP,
        'ipa': IPALDAP,
        'rhds': RHDSLDAP,
        'openldap': OpenLDAP,
    }

    logger = logging.getLogger(utils.Base.LOG_PREFIX)

    logger.info('Connecting to database')
    statement = engine.getStatement()

    with utils.FileTransaction() as filetransaction:
        with statement:
            aaadao = AAADAO(statement)

            logger.info('Sanity checks')
            if aaadao.isAuthzExists(args.authzName):
                raise RuntimeError(
                    "User/Group from domain '%s' exists in database" % (
                        args.authzName
                    )
                )

            logger.info('Loading options')
            domainEntry = utils.VdcOptions(statement).getDomainEntry(
                args.domain,
            )
            if not all([domainEntry.values()]):
                raise RuntimeError(
                    "Domain '%s' does not exists. Exiting." % args.domain
                )

            domainEntry['password'] = utils.OptionDecrypt(
                prefix=engine.prefix
            ).decrypt(
                domainEntry['password'],
            )
            if args.ldapServers:
                domainEntry['ldapServers'] = args.ldapServers

            driver = DRIVERS.get(domainEntry['provider'])
            if driver is None:
                raise RuntimeError(
                    "Provider '%s' is not supported" % domainEntry['provider']
                )

            driver = driver(utils.Kerberos(engine.prefix), args.domain)
            driver.connect(
                dnsDomain=args.domain,
                ldapServers=domainEntry['ldapServers'],
                saslUser=domainEntry['user'],
                bindUser=args.bindUser,
                bindPassword=(
                    args.bindPassword if args.bindPassword
                    else domainEntry['password']
                ),
                cacert=args.cacert
            )

            aaaprofile = AAAProfile(
                profile=args.profile,
                authnName=args.authnName,
                authzName=args.authzName,
                driver=driver,
                filetransaction=filetransaction,
                prefix=engine.prefix,
            )

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

            logger.info('Conversion completed')

            if args.cacert is None:
                logger.warning(
                    'We strongly suggest to enable SSL, '
                    'you can do this later, please refer to '
                    'ovirt-engine-extension-aaa-ldap documentation'
                )

            if domainEntry['provider'] != 'ad':
                logger.info(
                    'Conversion was done using single server. '
                    'Please refer to ovirt-engine-extension-aaa-ldap '
                    'documentation if you would like to apply failover or '
                    'other fallback policy.'
                )

            if not args.apply:
                raise RollbackError(
                    'Apply parameter was not specified rolling back'
                )


def main():
    args = parse_args()
    utils.setupLogger(log=args.log, debug=args.debug)
    logger = logging.getLogger(utils.Base.LOG_PREFIX)
    logger.debug('Arguments: %s', args)

    engine = utils.Engine(prefix=args.prefix)
    engine.setupEnvironment()
    ret = 1
    try:
        convert(args=args, engine=engine)
        ret = 0
    except RollbackError as e:
        logger.warning('%s', e)
    except Exception as e:
        logger.error('Conversion failed: %s', e)
        logger.debug('Exception', exc_info=True)
    return ret


if __name__ == '__main__':
    os.umask(0o022)
    sys.exit(main())


# vim: expandtab tabstop=4 shiftwidth=4
