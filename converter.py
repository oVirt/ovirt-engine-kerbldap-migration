#!/usr/bin/python
import base64
import glob
import logging
import os
import subprocess
import sys
import uuid
import datetime


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
            self._connection.rollback()
        else:
            self._connection.commit()
        self._connection.close()


class OptionDecrypt():

    def __init__(self, prefix='/'):
        pkcs12 = os.path.join(prefix, 'etc/pki/ovirt-engine/keys/engine.p12')
        password = 'mypass'
        self._rsa = RSA.load_key_string(
            subprocess.Popen(
                [
                    "openssl",
                    "pkcs12",
                    "-nocerts", "-nodes",
                    "-in", pkcs12,
                    "-passin", "pass:%s" % password,
                ],
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE
            ).communicate()[0]
        )

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
            self._get_option_for_domain(
                domain,
                'AdUserName',
            ).split('@')[0],
            self._get_option_for_domain(domain, 'AdUserId'),
            self._get_option_for_domain(domain, 'AdUserPassword'),
        )


class AAADAO(object):

    def __init__(self, statement):
        self._statement = statement

    def fetchLegacyUsers(self, legacy_domain):
        users = self._statement.execute(
            statement="""
                select
                    user_id,
                    username,
                    external_id,
                    last_admin_check_status,
                    active
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
        permission = self._statement.execute(
            statement="""
                select *
                from permissions
                where ad_element_id = %(legacy_id)s
            """,
            args=dict(
                legacy_id=legacy_id,
            ),
        )[0]

        return permission

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
        user['_create_date'] = user['_update_date'] = datetime.datetime.now()

        self._statement.execute(
            statement="""
                insert into users (
                    _create_date,
                    _update_date,
                    active,
                    department,
                    domain,
                    email,
                    external_id,
                    group_ids,
                    groups,
                    last_admin_check_status,
                    name,
                    namespace,
                    note,
                    role,
                    surname,
                    user_id,
                    username
                ) values (
                    %(_create_date)s,
                    %(_update_date)s,
                    %(active)s,
                    %(department)s,
                    %(domain)s,
                    %(email)s,
                    %(external_id)s,
                    '',
                    '',
                    %(last_admin_check_status)s,
                    %(name)s,
                    %(namespace)s,
                    '',
                    '',
                    %(surname)s,
                    %(user_id)s,
                    %(username)s
                )
            """,
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

    _username = None

    def __init__(self, domain):
        super(LDAP, self).__init__()
        self._domain = domain

    def getDomain(self):
        return self._domain

    def connect(self, username, password, uri):
        self.logger.debug("Connect uri='%s' user='%s'", uri, username)
        self._conn = ldap.initialize('ldap://%s' % uri)
        self._conn.protocol_version = ldap.VERSION3
        self._conn.simple_bind_s(username, password)
        self._username = username

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

    def getGroup(self, entryId):
        pass


class ADLDAP(LDAP):

    def __init__(self, domain):
        super(ADLDAP, self).__init__(domain)

    def connect(self, username, password):
        super(ADLDAP, self).connect(
            '%s@%s' % (
                username,
                self.getDomain()
            ),
            password,
            self.getDomain(),
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


class AAAProfile(Base):

    _TMP_SUFFIX = '.tmp'

    def __init__(
        self,
        profile,
        authnName,
        authzName,
        user,
        password,
        domain,
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
        self._vars = dict(
            authnName=authnName,
            authzName=authzName,
            profile=profile,
            configFile=os.path.join('..', '%s.properties' % profile),
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

    def checkExisting(self):
        for f in self._files:
            if os.path.exists(f):
                raise RuntimeError(
                    "File '%s' exists, exiting to avoid damage" % f
                )

    def save(self):
        def _writelog(f, s):
            self.logger.debug("Write '%s'\n%s", f, s)

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
                ).format(
                    provider='ad',  # TODO: AD specific
                    user=self._user,
                    password=self._password,
                    domain=self._domain,
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

    return args


def setupLogger(debug=False):
    logger = logging.getLogger(Base.LOG_PREFIX)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)

    try:
        h = logging.StreamHandler()
        if not debug:
            h.setLevel(logging.INFO)
            h.setFormatter(
                logging.Formatter(
                    fmt=(
                        '[%(levelname)-7s] '
                        '%(message)s'
                    ),
                ),
            )
        else:
            h.setLevel(logging.DEBUG)
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


def main():
    args = parse_args()
    setupLogger(debug=args.debug)
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
        #@ALON: fail if we have anything in database for authzName
        #before any change

        logger.info('Loading options')
        (
            user_name,
            user_id,
            password,
        ) = VdcOptions(statement).get_user_and_password_for_domain(args.domain)
        password = OptionDecrypt(prefix=args.prefix).decrypt(password)

        logger.info(
            "Connecting to ldap '%s' using '%s'",
            args.domain,
            user_name,
        )
        driver = ADLDAP(args.domain)
        driver.connect(user_name, password)

        with AAAProfile(
            profile=args.profile,
            authnName=args.authnName,
            authzName=args.authzName,
            user=driver.getUserName(),
            password=password,
            domain=args.domain,
            prefix=args.prefix,
        ) as aaaprofile:
            aaadao = AAADAO(statement)

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
                    e['domain'] = args.profile
                    e['last_admin_check_status'] = legacyUser[
                        'last_admin_check_status'
                    ]
                    e['active'] = legacyUser['active']
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
                    e['domain'] = args.profile
                    groups.append(e)

            logger.info('Converting permissions')
            permissions = []

            logger.info('Adding new users')
            for user in users:
                aaadao.insertUser(user)

                permission = aaadao.fetchLegacyPermissions(user['user_id.old'])
                permission['id'] = str(uuid.uuid4())
                permission['ad_element_id'] = user['user_id']
                permissions.append(permission)

            logger.info('Adding new groups')
            for group in groups:
                aaadao.insertGroup(group)

                permission = aaadao.fetchLegacyPermissions(group['id.old'])
                permission['id'] = str(uuid.uuid4())
                permission['ad_element_id'] = group['id']
                permissions.append(permission)

            logger.info('Adding new permissions')
            for permission in permissions:
                aaadao.insertPermission(permission)

            logger.info('Creating new extensions configuration')
            aaaprofile.save()

            if not args.apply:
                raise RuntimeError('Apply was not specified rolling back')
            logger.warn(
                'Please consider to setup ssl, as default configuration '
                'use plain'
            )

if __name__ == "__main__":
    main()


# vim: expandtab tabstop=4 shiftwidth=4