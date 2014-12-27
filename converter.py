#!/usr/bin/env python
import os
import sys
import ldap
import uuid
import base64
import argparse
import psycopg2
import psycopg2.extras
import subprocess

from M2Crypto import RSA


def parse_args():
    parser = argparse.ArgumentParser(
        description='Convert legacy users/groups with permissions into new extension api.'
    )
    parser.add_argument(
        '--prefix',
        default='/',
        help='for testing withing dev env'
    )
    parser.add_argument(
        '--domain',
        required=True,
        help='legacy domain name'
    )
    parser.add_argument(
        '--authn-name',
        help='authn extension name'
    )
    parser.add_argument(
        '--authz-extension',
        help='authz extension name'
    )
    parser.add_argument(
        '--profile',
        help='specify new profile name'
    )
    args = parser.parse_args(sys.argv[1:])
    if not args.authn_name:
        args.authn_name = '%s-authn' % args.domain

    if not args.authz_extension:
        args.authz_extension = '%s-authz' % args.domain

    if not args.profile:
        args.profile = '%s-new' % args.domain

    return args


class OptionDecrypt():

    def __init__(self, prefix):
        pkcs12 = os.path.join(prefix, 'etc/pki/ovirt-engine/keys/engine.p12')
        password = 'mypass'
        self._rsa = RSA.load_key_string(
            subprocess.check_output(
                args=(
                    "openssl",
                    "pkcs12",
                    "-nocerts", "-nodes",
                    "-in", pkcs12,
                    "-passin", "pass:%s" % password,
                ),
                stderr=subprocess.STDOUT,
            )
        )

    def decrypt(self, s):
        return self._rsa.private_decrypt(
            base64.b64decode(s),
            padding=RSA.pkcs1_padding,
        )


class User(object):
    """ This object represent one row in users table """
    legacy_id = None

    def __init__(self, row):
        self.__dict__.update(row)


class Group(object):
    """ This object represent one row in ad_groups table """
    legacy_id = None

    def __init__(self, row):
        self.__dict__.update(row)


class Statement(object):

    @property
    def environment(self):
        return self._environment

    def __init__(
        self,
        dbenvkeys,
        environment,
    ):
        super(Statement, self).__init__()
        self._environment = environment
        self._dbenvkeys = dbenvkeys

    def connect(
        self,
        host=None,
        port=None,
        secured=None,
        securedHostValidation=None,
        user=None,
        password=None,
        database=None,
    ):
        if host is None:
            host = self.environment[self._dbenvkeys['host']]
        if port is None:
            port = self.environment[self._dbenvkeys['port']]
        if secured is None:
            secured = self.environment[self._dbenvkeys['secured']]
        if securedHostValidation is None:
            securedHostValidation = self.environment[
                self._dbenvkeys['hostValidation']
            ]
        if user is None:
            user = self.environment[self._dbenvkeys['user']]
        if password is None:
            password = self.environment[self._dbenvkeys['password']]
        if database is None:
            database = self.environment[self._dbenvkeys['database']]

        sslmode = 'allow'
        if secured:
            if securedHostValidation:
                sslmode = 'verify-full'
            else:
                sslmode = 'require'

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

        return connection

    def execute(
        self,
        statement,
        args=dict(),
        host=None,
        port=None,
        secured=None,
        securedHostValidation=None,
        user=None,
        password=None,
        database=None,
        ownConnection=False,
        transaction=True,
    ):
        # autocommit member is available at >= 2.4.2
        def __backup_autocommit(connection):
            if hasattr(connection, 'autocommit'):
                return connection.autocommit
            else:
                return connection.isolation_level

        def __restore_autocommit(connection, v):
            if hasattr(connection, 'autocommit'):
                connection.autocommit = v
            else:
                connection.set_isolation_level(v)

        def __set_autocommit(connection, autocommit):
            if hasattr(connection, 'autocommit'):
                connection.autocommit = autocommit
            else:
                connection.set_isolation_level(
                    psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT
                    if autocommit
                    else
                    psycopg2.extensions.ISOLATION_LEVEL_READ_COMMITTED
                )

        ret = []
        old_autocommit = None
        _connection = None
        cursor = None
        try:
            if not ownConnection:
                connection = self.environment[self._dbenvkeys['connection']]
            else:

                _connection = connection = self.connect(
                    host=host,
                    port=port,
                    secured=secured,
                    securedHostValidation=securedHostValidation,
                    user=user,
                    password=password,
                    database=database,
                )

            if not transaction:
                old_autocommit = __backup_autocommit(connection)
                __set_autocommit(connection, True)

            cursor = connection.cursor()
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

        except:
            if _connection is not None:
                _connection.rollback()
            raise
        else:
            if _connection is not None:
                _connection.commit()
        finally:
            if old_autocommit is not None and connection is not None:
                __restore_autocommit(connection, old_autocommit)
            if cursor is not None:
                cursor.close()
            if _connection is not None:
                _connection.close()

        return ret


class DBUtils(object):

    def __init__(self, statement):
        self.statement = statement

    def __get_x_for_domain(self, domain, val):
        x = None
        result = self.statement.execute(
            statement="""
                SELECT option_value from vdc_options where option_name = %(val)s
            """,
            args=dict(
                val=val
            ),
            ownConnection=True,
            transaction=False,
        )
        if len(result) <= 0:
            return None

        result = result[0]['option_value']
        for val in result.split(','):
            if val.startswith(domain):
                x = val[val.find(':') + 1:]
                break

        return x

    def __get_password_for_domain(self, domain, prefix):
        return OptionDecrypt(prefix).decrypt(
            self.__get_x_for_domain(domain, 'AdUserPassword')
        )

    def __get_user_for_domain(self, domain):
        username = self.__get_x_for_domain(domain, 'AdUserName')
        return username[:username.find('@')]

    def get_user_and_password_for_domain(self, domain, prefix):
        user = self.__get_user_for_domain(domain)
        password = self.__get_password_for_domain(domain, prefix)

        return user, password

    def get_legacy_users(self, legacy_domain):
        users = self.statement.execute(
            statement="""
                SELECT * FROM users WHERE domain = %(legacy_domain)s
            """,
            args=dict(
                legacy_domain=legacy_domain,
            ),
            ownConnection=True,
            transaction=False,
        )

        return [User(user) for user in users]

    def get_legacy_groups(self, legacy_domain):
        groups = self.statement.execute(
            statement="""
                SELECT * FROM ad_groups WHERE domain = %(legacy_domain)s
            """,
            args=dict(
                legacy_domain=legacy_domain,
            ),
            ownConnection=True,
            transaction=False,
        )

        return [Group(group) for group in groups]

    def insert_new_perm(self, legacy_id, new_id):
        permission = self.statement.execute(
            statement="""
                SELECT * FROM permissions WHERE ad_element_id =%(legacy_id)s
            """,
            args=dict(
                legacy_id=legacy_id,
            ),
            ownConnection=True,
            transaction=False,
        )[0]

        self.statement.execute(
            statement="""
                INSERT INTO permissions (
                    id, role_id, ad_element_id, object_id, object_type_id
                ) VALUES (
                    %(id)s,
                    %(role_id)s,
                    %(ad_element_id)s,
                    %(object_id)s,
                    %(object_type_id)s
                )
            """,
            args=dict(
                id=str(uuid.uuid4()),
                role_id=permission['role_id'],
                ad_element_id=new_id,
                object_id=permission['object_id'],
                object_type_id=permission['object_type_id']
            ),
            ownConnection=True,
            transaction=False,
        )

    def insert_new_perms(self, useridsmap):
        for userid_map in useridsmap:
            self.insert_new_perm(
                userid_map[0],
                userid_map[1]
            )

    def insert_new_user(self, user):
        self.statement.execute(
            statement="""
                INSERT INTO users (
                    user_id, name, surname,
                    domain, username, groups,
                    department, role, email,
                    note, last_admin_check_status,
                    group_ids, external_id, active,
                    _create_date, _update_date,
                    namespace
                ) VALUES (
                    %(user_id)s, %(name)s, %(surname)s,
                    %(domain)s, %(username)s, %(groups)s,
                    %(department)s, %(role)s, %(email)s,
                    %(note)s, %(last_admin_check_status)s,
                    %(group_ids)s, %(external_id)s, %(active)s,
                    %(_create_date)s, %(_update_date)s,
                    %(namespace)s
                )
         """,
            args=dict(
                user_id=user.user_id,
                name=user.name,
                surname=user.surname,
                domain=user.domain,
                username=user.username,
                groups=user.groups,
                department=user.department,
                role=user.role,
                email=user.email,
                note=user.note,
                last_admin_check_status=user.last_admin_check_status,
                group_ids=user.group_ids,
                external_id=user.external_id,
                active=user.active,
                _create_date=user._create_date,
                _update_date=user._update_date,
                namespace=user.namespace
            ),
            ownConnection=True,
            transaction=False,
        )

    def insert_new_group(self, group):
        self.statement.execute(
            statement="""
                INSERT INTO ad_groups (
                    id, name, domain, distinguishedname, external_id, namespace
                ) VALUES (
                    %(id)s,
                    %(name)s,
                    %(domain)s,
                    %(distinguishedname)s,
                    %(external_id)s,
                    %(namespace)s
                )
            """,
            args=dict(
                id=group.id,
                name=group.name,
                domain=group.domain,
                distinguishedname=group.distinguishedname,
                external_id=group.external_id,
                namespace=group.namespace
            ),
            ownConnection=True,
            transaction=False,
        )


class LDAP(object):

    def connect(self, username, password, uri):
        self.conn = ldap.initialize('ldap://%s:389' % uri)
        self.conn.protocol_version = ldap.VERSION3

        self.conn.simple_bind_s(username, password)
        #self.conn.whoami_s()

    def _get_default_naming_context(self):
        result = self.conn.search_s(
            '',
            ldap.SCOPE_BASE,
            '(objectclass=*)',
            ['defaultNamingContext']
        )
        return result[0][1]['defaultNamingContext'][0]


class ADLDAP(LDAP):

    def __get_conf_naming_context(self):
        result = self.conn.search_s(
            '',
            ldap.SCOPE_BASE,
            '(objectclass=*)',
            ['configurationNamingContext']
        )
        return result[0][1]['configurationNamingContext'][0]

    def get_namespaces(self):
        conf_name_context = self.__get_conf_naming_context()
        result = self.conn.search_s(
            'CN=Partitions,%s' % conf_name_context,
            ldap.SCOPE_SUBTREE,
            '(&(objectClass=crossRef)(nETBIOSName=*))',
            ['nCName']
        )
        return [res[1]['nCName'][0] for res in result]

    def get_ldap_user(self, search_base, legacyuser):
        result = self.conn.search_s(
            'CN=Users,%s' % search_base,
            ldap.SCOPE_SUBTREE,
            '(&(givenName=%s)(sn=%s))' % (legacyuser.name, legacyuser.surname)
        )
        return result[0][1]

    def get_ldap_user_dn(self, search_base, user):
        result = self.conn.search_s(
            'CN=Users,%s' % search_base,
            ldap.SCOPE_SUBTREE,
            '(cn=%s)' % user,
            ['distinguishedName']
        )
        return result[0][1]

    def get_ldap_group(self, search_base, legacygroup):
        group_name = legacygroup.name[legacygroup.name.rfind('/') + 1 : legacygroup.name.find('@')]
        result = self.conn.search_s(
            'CN=Users,%s' % search_base,
            ldap.SCOPE_SUBTREE,
            '(name=%s)' % group_name
        )
        return result[0][1]


class Transform(object):

    def __init__(self):
        self.namespaces = []
        self.ad = None

    def connect(self, user, password, domain):
        username = '%s@%s' % (user, domain)
        self.ad = ADLDAP()
        self.ad.connect(username, password, domain)

    def obtain_namespaces(self):
        self.namespaces = self.ad.get_namespaces()

    def get_user_dn(self, user):
        return self.ad.get_ldap_user_dn(
            self.ad._get_default_naming_context(),
            user
        )['distinguishedName'][0]

    def transform_group(self, legacygroup, newdomain):
        legacygroup.legacy_id = legacygroup.id
        legacygroup.id = str(uuid.uuid4())
        legacygroup.domain = newdomain

        if legacygroup.distinguishedname is None:
            legacygroup.distinguishedname = ''

        # Actually, search within default naming context, since legacy do it
        default_naming_context = self.ad._get_default_naming_context()
        group = self.ad.get_ldap_group(
            default_naming_context,
            legacygroup
        )

        legacygroup.name = group['name'][0]
        legacygroup.namespace = self.find_user_namespace(group['distinguishedName'][0])
        legacygroup.external_id = base64.b64encode(group['objectGUID'][0])

        return legacygroup

    def transform_user(self, legacyuser, newdomain):
        legacyuser.legacy_id = legacyuser.user_id
        legacyuser.user_id = str(uuid.uuid4())
        legacyuser.domain = newdomain
        legacyuser.group_ids = ''
        legacyuser.groups = ''

        if legacyuser.department is None:
            legacyuser.department = ''
        if legacyuser.email is None:
            legacyuser.email = ''

        # Actually, search within default naming context, since legacy do it
        default_naming_context = self.ad._get_default_naming_context()
        user = self.ad.get_ldap_user(
            default_naming_context,
            legacyuser
        )

        legacyuser.username = user['userPrincipalName'][0]
        legacyuser.namespace = self.find_user_namespace(user['distinguishedName'][0])
        legacyuser.external_id = base64.b64encode(user['objectGUID'][0])

        return legacyuser

    def find_user_namespace(self, user_dn):
        candidate = ""
        for namespace in self.namespaces:
            if user_dn.endswith("," + namespace) and len(namespace) > len(candidate):
                candidate = namespace
        return candidate if candidate else None


def transform_users(dbutil, transform, args, legacy_ids_map):
    legacyusers = dbutil.get_legacy_users(args.domain)

    for legacyuser in legacyusers:
        new_user = transform.transform_user(legacyuser, args.authz_extension)
        dbutil.insert_new_user(new_user)
        legacy_ids_map.append([new_user.legacy_id, new_user.user_id])


def transform_groups(dbutil, transform, args, legacy_ids_map):
    legacygroups = dbutil.get_legacy_groups(args.domain)

    for legacygroup in legacygroups:
        new_group = transform.transform_group(legacygroup, args.authz_extension)
        dbutil.insert_new_group(new_group)
        legacy_ids_map.append([new_group.legacy_id, new_group.id])


def transform_permissions(dbutil, idsmap):
    dbutil.insert_new_perms(idsmap)

ENGINE_DB_ENV_KEYS = {
    'host': 'host',
    'port': 'port',
    'secured': 'secured',
    'hostValidation': 'hostValidation',
    'user': 'user',
    'password': 'password',
    'database': 'database',
}

ENGINE_DB_ENV = {
    'host': '10.34.63.31',
    'port': '5432',
    'secured': False,
    'hostValidation': False,
    'user': 'postgres',
    'password': '',
    'database': 'engine',
}


class AAAProfile(object):

    EXT_PATH = '/etc/ovirt-engine/extensions.d/'

    def __init__(self, profile, authn, authz):
        self.profile = profile
        self.authn = authn
        self.authz = authz

    def create_authz(self):
        file = os.path.join(self.EXT_PATH, '%s.properties' % self.authz)
        config = os.path.join(self.EXT_PATH, 'conf_%s.properties' % self.profile)
        with open(file, 'w') as authz_file:
            authz_file.write("ovirt.engine.extension.enabled = true\n")
            authz_file.write("ovirt.engine.extension.name = %s\n" % self.authz)
            authz_file.write("ovirt.engine.extension.bindings.method = jbossmodule\n")
            authz_file.write("ovirt.engine.extension.binding.jbossmodule.module = org.ovirt.engine-extensions.aaa.ldap\n")
            authz_file.write("ovirt.engine.extension.binding.jbossmodule.class = org.ovirt.engineextensions.aaa.ldap.AuthzExtension\n")
            authz_file.write("ovirt.engine.extension.provides = org.ovirt.engine.api.extensions.aaa.Authz\n")
            authz_file.write("config.profile.file.1 = %s\n" % config)

    def create_authn(self):
        file = os.path.join(self.EXT_PATH, '%s.properties' % self.authn)
        config = os.path.join(self.EXT_PATH, 'conf_%s.properties' % self.profile)
        with open(file, 'w') as authn_file:
            authn_file.write("ovirt.engine.extension.enabled = true\n")
            authn_file.write("ovirt.engine.extension.name = %s\n" % self.profile)
            authn_file.write("ovirt.engine.extension.bindings.method = jbossmodule\n")
            authn_file.write("ovirt.engine.extension.binding.jbossmodule.module = org.ovirt.engine-extensions.aaa.ldap\n")
            authn_file.write("ovirt.engine.extension.binding.jbossmodule.class = org.ovirt.engineextensions.aaa.ldap.AuthnExtension\n")
            authn_file.write("ovirt.engine.extension.provides = org.ovirt.engine.api.extensions.aaa.Authn\n")
            authn_file.write("config.profile.file.1 = %s\n" % config)
            authn_file.write("ovirt.engine.aaa.authn.profile.name = %s\n" % self.authn)
            authn_file.write("ovirt.engine.aaa.authn.authz.plugin = %s\n" % self.authz)

    def create_config(self, user, password, domain, provider='ad'):
        config = os.path.join(self.EXT_PATH, 'conf_%s.properties' % self.profile)
        with open(config, 'w') as conf_file:
            conf_file.write("include = <%s.properties>\n\n" % provider)
            conf_file.write("vars.user = %s\n" % user)
            conf_file.write("vars.password = %s\n" % password)
            conf_file.write("vars.domain = %s\n\n" % domain)
            conf_file.write("pool.default.serverset.type = single\n")
            conf_file.write("pool.default.serverset.single.server = ${global:vars.domain}\n")
            conf_file.write("pool.default.auth.type = simple\n")
            conf_file.write("pool.default.auth.simple.bindDN = ${global:vars.user}\n")
            conf_file.write("pool.default.auth.simple.password = ${global:vars.password}\n")


def main(args):
    statement = Statement(
        dbenvkeys=ENGINE_DB_ENV_KEYS,
        environment=ENGINE_DB_ENV,
    )
    dbutil = DBUtils(statement)
    user, password = dbutil.get_user_and_password_for_domain(
        args.domain, args.prefix
    )

    transform = Transform()
    transform.connect(user, password, args.domain)
    transform.obtain_namespaces()
    user_dn = transform.get_user_dn(user)

    aaaprofile = AAAProfile(args.profile, args.authn_name, args.authz_extension)
    aaaprofile.create_authn()
    aaaprofile.create_authz()
    aaaprofile.create_config(user_dn, password, args.domain)

    legacy_ids_map = []
    transform_users(dbutil, transform, args, legacy_ids_map)
    transform_groups(dbutil, transform, args, legacy_ids_map)
    transform_permissions(dbutil, legacy_ids_map)


if __name__ == "__main__":
    cmd_args = parse_args()
    main(cmd_args)

