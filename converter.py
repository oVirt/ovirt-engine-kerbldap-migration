#!/usr/bin/python
import base64
import glob
import logging
import os
import subprocess
import sys
import uuid


from M2Crypto import RSA


try:
    import psycopg2
    import psycopg2.extras
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
            self._connection.commit()
        else:
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

    def _get_option_for_domain(self, domain, val):
        ret = None

        result = self._statement.execute(
            statement="""
                select option_value
                from vdc_options
                where option_name = %(val)s
            """,
            args=dict(
                val=val,
            ),
        )
        if result:
            result = result[0]['option_value']
            for val in result.split(','):
                if val.startswith(domain + ':'):
                    ret = val.split(':', 1)[1]
                    break

        return ret

    def get_user_and_password_for_domain(self, domain):
        return (
            self._get_option_for_domain(domain, 'AdUserName'),
            self._get_option_for_domain(domain, 'AdUserId'),
            self._get_option_for_domain(domain, 'AdUserPassword'),
        )

    def get_provider_type(self, domain):
        provider = self._get_option_for_domain(domain, 'LDAPProviderTypes')
        if provider == 'activeDirectory':
            provider = 'ad'

        return provider.lower()


class AAADAO(object):

    def __init__(self, statement, legacy):
        self._statement = statement
        self._legacy = legacy

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

    def fetchLegacyPermissions(self, legacy_id):
        ret = None

        permissions = self._statement.execute(
            statement="""
                select *
                from permissions
                where ad_element_id = %(legacy_id)s
            """,
            args=dict(
                legacy_id=legacy_id,
            ),
        )
        if permissions:
            ret = permissions

        return ret

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
                legacyNames="""
                    active,
                    group_ids,
                    groups,
                    role,
                """ if self._legacy else '',
                legacyValues="""
                    True,
                    '',
                    '',
                    '',
                """ if self._legacy else '',
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


class Kinit():

    def __init__(self, username, password):
        self._username = username
        self._password = password

    def login(self):
        p = subprocess.Popen(
            [
                '-c',
                """
                KRB5_CONFIG=/etc/ovirt-engine/krb5.conf
                echo {password} |
                kinit {username}
                """.format(
                    username=self._username,
                    password=self._password
                )
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
        )
        stdout, stderr = p.communicate()
        if p.wait() != 0:
            raise RuntimeError('Failed to execute kinit')


class LDAP(Base):

    _username = None

    def __init__(self, domain):
        super(LDAP, self).__init__()
        self._domain = domain

    def getDomain(self):
        return self._domain

    def connect(self, username, password, uri, cacert=None):
        self.connectSimple(username, password, uri, cacert)

    def connectSimple(self, username, password, uri, cacert=None):
        self.logger.debug("Connect uri='%s' user='%s'", uri, username)
        self._conn = ldap.initialize('ldap://%s' % uri)
        if cacert is not None:
            self._conn.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
            self._conn.set_option(
                ldap.OPT_X_TLS_REQUIRE_CERT,
                ldap.OPT_X_TLS_DEMAND
            )
            # does not work per connection?
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, cacert)
            self._conn.start_tls_s()
        self._conn.simple_bind_s(username, password)
        self._username = username

    def connectGssapi(self, username, password, uri):
        # Note you need cyrus-sasl-gssapi package
        kinit = Kinit(username, password)
        kinit.login()

        self.logger.debug("Connect uri='%s' user='%s'", uri, username)
        self._conn = ldap.initialize('ldap://%s' % uri)
        auth = ldap.sasl.gssapi("")
        self._conn.sasl_interactive_bind_s("", auth)

    def search(self, baseDN, scope, filter, attributes):
        self.logger.debug(
            "Search baseDN='%s', scope=%s, filter='%s', attributes=%s'",
            baseDN,
            scope,
            filter,
            attributes,
        )
        ret = self._conn.search_s(baseDN, scope, filter, attributes)
        self.logger.debug('SearchResult: %s', ret)
        return ret

    def getUserName(self):
        return self._username

    def getNamespace(self):
        pass

    def getUser(self, entryId):
        pass

    def getUserDN(self, entryId):
        pass

    def getGroup(self, entryId):
        pass


class IPALDAP(LDAP):

    def __init__(self, domain):
        super(IPALDAP, self).__init__(domain)

    def connect(self, username, password, cacert):
        super(IPALDAP, self).connectGssapi(
            username,
            password,
            self.getDomain(),
        )
        self._conn.set_option(ldap.OPT_REFERRALS, 0)
        self._namespace = self.search(
            '',
            ldap.SCOPE_BASE,
            '(objectClass=*)',
            ['defaultnamingcontext'],
        )[0][1]['defaultnamingcontext'][0]

    def _getEntryById(self, fields, entryId):
        ret = None
        result = self.search(
            self._namespace,
            ldap.SCOPE_SUBTREE,
            '(ipaUniqueID=%s)' % entryId,
            fields,
        )
        if result:
            ret = result[0][1]
            ret['dn'] = result[0][0]
        return ret

    def getNamespace(self):
        return self._namespace

    def getUser(self, entryId):
        user = self._getEntryById(
            fields=[
                'displayName',
                'givenName',
                'mail',
                'cn',
                'ipaUniqueID',
                'sn',
                'dn',
            ],
            entryId=entryId,
        )
        return dict(
            department='',  # TODO: is this in IPA entry?
            email=user.get('mail', [''])[0],
            external_id=base64.b64encode(user['ipaUniqueID'][0]),
            name=user.get('cn', [''])[0],
            namespace=self.getNamespace(),
            surname=user.get('sn', [''])[0],
            user_id=str(uuid.uuid4()),
            username=user.get('dn', ['']),
        )

    def getUserDN(self, entryId):
        return self.getUser(entryId)['username']

    def getGroup(self, entryId):
        group = self._getEntryById(
            fields=[
                'description',
                'cn',
                'ipaUniqueID',
            ],
            entryId=entryId,
        )
        return dict(
            description=group.get('description', [''])[0],
            external_id=base64.b64encode(group['ipaUniqueID'][0]),
            id=str(uuid.uuid4()),
            name=group.get('cn', [''])[0],
            namespace=self.getNamespace(),
        )


class ADLDAP(LDAP):

    def __init__(self, domain):
        super(ADLDAP, self).__init__(domain)

    def connect(self, username, password, cacert):
        super(ADLDAP, self).connect(
            '%s@%s' % (
                username.split('@')[0],  # Get rid of realm
                self.getDomain()
            ),
            password,
            self.getDomain(),
            cacert,
        )
        self._conn.set_option(ldap.OPT_REFERRALS, 0)
        self._configurationNamingContext = self.search(
            '',
            ldap.SCOPE_BASE,
            '(objectclass=*)',
            ['configurationNamingContext']
        )[0][1]['configurationNamingContext'][0]
        self._namespace = self.search(
            'CN=Partitions,%s' % self._configurationNamingContext,
            ldap.SCOPE_SUBTREE,
            '(&(objectClass=crossRef)(dnsRoot=%s)(nETBIOSName=*))' % (
                self.getDomain(),
            ),
            ['nCName'],
        )[0][1]['nCName'][0]

    def _getEntryById(self, fields, entryId):
        ret = None
        result = self.search(
            self._namespace,
            ldap.SCOPE_SUBTREE,
            '(objectGUID=%s)' % ldap.filter.escape_filter_chars(
                uuid.UUID(entryId).bytes_le
            ),
            fields,
        )
        if result:
            ret = result[0][1]
        return ret

    def getNamespace(self):
        return self._namespace

    def getUser(self, entryId):
        user = self._getEntryById(
            fields=[
                'department',
                'displayName',
                'givenName',
                'mail',
                'name',
                'objectGUID',
                'sn',
                'title',
                'userPrincipalName',
            ],
            entryId=entryId,
        )
        return dict(
            department=user.get('department', [''])[0],
            email=user.get('mail', [''])[0],
            external_id=base64.b64encode(user['objectGUID'][0]),
            name=user.get('name', [''])[0],
            namespace=self.getNamespace(),
            surname=user.get('sn', [''])[0],
            user_id=str(uuid.uuid4()),
            username=user.get('userPrincipalName', [''])[0],
        )

    def getUserDN(self, entryId):
        return self.getUser(entryId)['username']

    def getGroup(self, entryId):
        group = self._getEntryById(
            fields=[
                'description',
                'name',
                'objectGUID',
            ],
            entryId=entryId,
        )
        return dict(
            description=group.get('description', [''])[0],
            external_id=base64.b64encode(group['objectGUID'][0]),
            id=str(uuid.uuid4()),
            name=group.get('name', [''])[0],
            namespace=self.getNamespace(),
        )


class LDAPDriver():

    @staticmethod
    def createDriver(domain, provider):
        if provider == 'ad':
            return ADLDAP(domain)
        elif provider == 'ipa':
            return IPALDAP(domain)
        else:
            raise RuntimeError("No such provider '%s'" % provider)


class AAAProfile(Base):

    _TMP_SUFFIX = '.tmp'

    def __init__(
        self,
        profile,
        authnName,
        authzName,
        user,
        provider,
        password,
        domain,
        cacert=None,
        prefix='/',
    ):
        super(AAAProfile, self).__init__()

        extensionsDir = os.path.join(
            prefix,
            'etc/ovirt-engine/extensions.d',
        )
        self._user = user
        self._password = password
        self._domain = domain
        self._cacert = cacert
        self._provider = provider
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
            authzFile=os.path.join(
                extensionsDir,
                '%s.properties' % authzName
            ),
            authnFile=os.path.join(
                extensionsDir,
                '%s.properties' % authnName
            ),
        )
        if self._cacert is not None:
            self._files['trustStore'] = os.path.join(
                extensionsDir,
                '..',
                'aaa',
                'ca.jks',
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
            _writelog(
                f,
                (
                    "include = <{provider}.properties>\n"
                    "\n"
                    "self._vars.user = {user}\n"
                    "self._vars.password = {password}\n"
                    "self._vars.domain = {domain}\n"
                    "\n"
                    "pool.default.serverset.type = single\n"

                    "pool.default.serverset.single.server = "
                    "${{global:self._vars.domain}}\n"

                    "pool.default.auth.type = simple\n"

                    "pool.default.auth.simple.bindDN = "
                    "${{global:self._vars.user}}\n"

                    "pool.default.auth.simple.password = "
                    "${{global:self._vars.password}}\n"

                    "pool.default.ssl.startTLS = {startTLS}\n"

                    "pool.default.ssl.truststore.file = "
                    "${{local:_basedir}}/ca.jks\n"

                    "pool.default.ssl.truststore.password = changeit"
                ).format(
                    provider=self._provider,
                    user=self._user,
                    password=self._password,
                    domain=self._domain,
                    startTLS='true' if self._cacert else 'false',
                )
            )

    def __enter__(self):
        self.checkExisting()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            for f in self._files.values():
                os.rename('%s%s' % (f, self._TMP_SUFFIX), f)
        else:
            for f in self._files.values():
                tmp_file = '%s%s' % (f, self._TMP_SUFFIX)
                if os.path.exists(tmp_file):
                    os.unlink(tmp_file)


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
        help='for testing withing dev env'
    )
    parser.add_argument(
        '--debug',
        default=False,
        action='store_true',
        help='enable debug log'
    )
    parser.add_argument(
        '--log',
        metavar='FILE',
        default=None,
        help='write log into file'
    )
    parser.add_argument(
        '--legacy',
        default=False,
        action='store_true',
        help='use legacy engine'
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
        help='domain name to convert'
    )
    parser.add_argument(
        '--authn-name',
        dest='authnName',
        help='authn extension name, default profile name with -authn suffix'
    )
    parser.add_argument(
        '--authz-name',
        dest='authzName',
        help='authz extension name, default profile name with -authz suffix'
    )
    parser.add_argument(
        '--profile',
        dest='profile',
        help='new profile name, default old profile name with -new suffix'
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
        aaadao = AAADAO(statement, args.legacy)
        if aaadao.isDomainExists(args.authzName):
            raise RuntimeError(
                "User/Group from domain '%s' exists in database" % args.domain
            )
        vdcoptions = VdcOptions(statement)
        logger.info('Loading options')
        (
            user_name,
            user_id,
            password,
        ) = vdcoptions.get_user_and_password_for_domain(args.domain)
        provider = vdcoptions.get_provider_type(args.domain)
        if not all([user_name, user_id, password]):
            raise RuntimeError(
                "Domain '%s' does not exists. Exiting." % args.domain
            )

        password = OptionDecrypt(prefix=args.prefix).decrypt(password)

        logger.info(
            "Connecting to ldap '%s' using '%s'",
            args.domain,
            user_name,
        )
        driver = LDAPDriver.createDriver(args.domain, provider)
        driver.connect(
            user_name,
            password,
            cacert=args.cacert
        )

        with AAAProfile(
            profile=args.profile,
            authnName=args.authnName,
            authzName=args.authzName,
            user=driver.getUserDN(user_id),
            provider=provider,
            password=password,
            domain=args.domain,
            cacert=args.cacert,
            prefix=args.prefix,
        ) as aaaprofile:
            logger.info('Converting users')
            users = []
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
                    e['user_id.old'] = legacyUser['user_id']
                    e['domain'] = args.authzName
                    e['last_admin_check_status'] = legacyUser[
                        'last_admin_check_status'
                    ]
                    users.append(e)

            logger.info('Converting groups')
            groups = []
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
                    e['id.old'] = legacyGroup['id']
                    e['domain'] = args.authzName
                    groups.append(e)

            logger.info('Converting permissions')
            permissions = []
            for user in users:
                perms = aaadao.fetchLegacyPermissions(user['user_id.old'])
                if perms is not None:
                    for perm in perms:
                        perm['id'] = str(uuid.uuid4())
                        perm['ad_element_id'] = user['user_id']
                        permissions.append(perm)

            for group in groups:
                perms = aaadao.fetchLegacyPermissions(group['id.old'])
                if perms is not None:
                    for perm in perms:
                        perm['id'] = str(uuid.uuid4())
                        perm['ad_element_id'] = group['id']
                        permissions.append(perm)

            logger.info('Adding new users')
            for user in users:
                aaadao.insertUser(user)

            logger.info('Adding new groups')
            for group in groups:
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
                    'site-packages'
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
