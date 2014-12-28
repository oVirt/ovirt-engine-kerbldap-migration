#!/usr/bin/python
import base64
import glob
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
except ImportError:
    raise RuntimeError('Please install python-ldap')


class Statement(object):

    _connection = None

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
            subprocess.Popen([
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


class DBUtils(object):

    def __init__(self, statement, optionDecrypt):
        self._statement = statement
        self._optionDecrypt = optionDecrypt

    def __get_x_for_domain(self, domain, val):
        x = None
        result = self._statement.execute(
            statement="""
                select option_value
                from vdc_options
                where option_name = %(val)s
            """,
            args=dict(
                val=val
            ),
        )
        if len(result) <= 0:
            return None

        result = result[0]['option_value']
        for val in result.split(','):
            if val.startswith(domain):
                x = val[val.find(':') + 1:]
                break

        return x

    def __get_password_for_domain(self, domain):
        return self._optionDecrypt.decrypt(
            self.__get_x_for_domain(domain, 'AdUserPassword')
        )

    def __get_user_name_for_domain(self, domain):
        username = self.__get_x_for_domain(domain, 'AdUserName')
        return username[:username.find('@')]

    def __get_user_id_for_domain(self, domain):
        return self.__get_x_for_domain(domain, 'AdUserId')

    def get_user_and_password_for_domain(self, domain):
        user_name = self.__get_user_name_for_domain(domain)
        user_id = self.__get_user_id_for_domain(domain)
        password = self.__get_password_for_domain(domain)

        return user_name, user_id, password

    def get_legacy_users(self, legacy_domain):
        users = self._statement.execute(
            statement="""
                select *
                from users
                where domain = %(legacy_domain)s
            """,
            args=dict(
                legacy_domain=legacy_domain,
            ),
        )

        return users

    def get_legacy_groups(self, legacy_domain):
        groups = self._statement.execute(
            statement="""
                select * from ad_groups
                where domain = %(legacy_domain)s
            """,
            args=dict(
                legacy_domain=legacy_domain,
            ),
        )

        return groups

    def insert_new_perm(self, legacy_id, new_id):
        permission = self._statement.execute(
            statement="""
                select *
                from permissions
                where ad_element_id =%(legacy_id)s
            """,
            args=dict(
                legacy_id=legacy_id,
            ),
        )[0]

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
            args=dict(
                id=str(uuid.uuid4()),
                role_id=permission['role_id'],
                ad_element_id=new_id,
                object_id=permission['object_id'],
                object_type_id=permission['object_type_id']
            ),
        )

    def insert_new_perms(self, useridsmap):
        for userid_map in useridsmap:
            self.insert_new_perm(
                userid_map[0],
                userid_map[1]
            )

    def insert_new_user(self, user):
        self._statement.execute(
            statement="""
                insert into users (
                    user_id, name, surname,
                    domain, username, groups,
                    department, role, email,
                    note, last_admin_check_status,
                    group_ids, external_id, active,
                    _create_date, _update_date,
                    namespace
                ) values (
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
                user_id=user['user_id'],
                name=user['name'],
                surname=user['surname'],
                domain=user['domain'],
                username=user['username'],
                groups=user['groups'],
                department=user['department'],
                role=user['role'],
                email=user['email'],
                note=user['note'],
                last_admin_check_status=user['last_admin_check_status'],
                group_ids=user['group_ids'],
                external_id=user['external_id'],
                active=user['active'],
                _create_date=user['_create_date'],
                _update_date=user['_update_date'],
                namespace=user['namespace']
            ),
        )

    def insert_new_group(self, group):
        self._statement.execute(
            statement="""
                insert into ad_groups (
                    id,
                    name,
                    domain,
                    distinguishedname,
                    external_id,
                    namespace
                ) values (
                    %(id)s,
                    %(name)s,
                    %(domain)s,
                    %(distinguishedname)s,
                    %(external_id)s,
                    %(namespace)s
                )
            """,
            args=dict(
                id=group['id'],
                name=group['name'],
                domain=group['domain'],
                distinguishedname=group['distinguishedname'],
                external_id=group['external_id'],
                namespace=group['namespace']
            ),
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

    # TODO: AD specific
    def get_ldap_user(self, search_base, legacyuser_id):
        objectGuid = uuid.UUID(legacyuser_id).bytes_le
        objectGuid = ldap.filter.escape_filter_chars(objectGuid)

        result = self.conn.search_s(
            'CN=Users,%s' % search_base,
            ldap.SCOPE_SUBTREE,
            '(objectGUID=%s)' % objectGuid
        )
        return result[0][1]

    def get_ldap_group(self, search_base, legacygroup_id):
        objectGuid = uuid.UUID(legacygroup_id).bytes_le
        objectGuid = ldap.filter.escape_filter_chars(objectGuid)

        result = self.conn.search_s(
            'CN=Users,%s' % search_base,
            ldap.SCOPE_SUBTREE,
            '(objectGUID=%s)' % objectGuid
        )
        return result[0][1]


class Transform(object):

    def __init__(self):
        self._namespaces = []
        self._ad = None

    def connect(self, user, password, domain):
        username = '%s@%s' % (user, domain)
        self._ad = ADLDAP()
        self._ad.connect(username, password, domain)

    def obtain_namespaces(self):
        self._namespaces = self._ad.get_namespaces()

    def get_user_dn(self, user):
        return self._ad.get_ldap_user(
            self._ad._get_default_naming_context(),
            user
        )['distinguishedName'][0]

    def transform_group(self, legacygroup, newdomain):
        legacygroup['legacy_id'] = legacygroup['id']
        legacygroup['id'] = str(uuid.uuid4())
        legacygroup['domain'] = newdomain

        if legacygroup['distinguishedname'] is None:
            legacygroup['distinguishedname'] = ''

        # Actually, search within default naming context, since legacy do it
        default_naming_context = self._ad._get_default_naming_context()
        group = self._ad.get_ldap_group(
            default_naming_context,
            legacygroup['external_id']
        )

        legacygroup['name'] = group['name'][0]
        legacygroup['namespace'] = self.find_user_namespace(
            group['distinguishedName'][0]
        )
        # TODO: AD specific
        legacygroup['external_id'] = base64.b64encode(group['objectGUID'][0])

        return legacygroup

    def transform_user(self, legacyuser, newdomain):
        legacyuser['legacy_id'] = legacyuser['user_id']
        legacyuser['user_id'] = str(uuid.uuid4())
        legacyuser['domain'] = newdomain
        legacyuser['group_ids'] = ''
        legacyuser['groups'] = ''

        if legacyuser['department'] is None:
            legacyuser['department'] = ''
        if legacyuser['email'] is None:
            legacyuser['email'] = ''

        # Actually, search within default naming context, since legacy do it
        default_naming_context = self._ad._get_default_naming_context()
        user = self._ad.get_ldap_user(
            default_naming_context,
            legacyuser['external_id']
        )

        legacyuser['username'] = user['userPrincipalName'][0]
        legacyuser['namespace'] = self.find_user_namespace(
            user['distinguishedName'][0]
        )
        # TODO: active directory specific
        legacyuser['external_id'] = base64.b64encode(user['objectGUID'][0])

        return legacyuser

    def find_user_namespace(self, user_dn):
        candidate = ""
        for namespace in self._namespaces:
            if (
                user_dn.endswith("," + namespace) and
                len(namespace) > len(candidate)
            ):
                candidate = namespace
        return candidate if candidate else None


class Transform2():

    def __init__(self, dbutil, transform, domain, authzName):
        self._dbutil = dbutil
        self._transform = transform
        self._domain = domain
        self._authzName = authzName

    def transform_users(self, legacy_ids_map):
        legacyusers = self._dbutil.get_legacy_users(self._domain)

        for legacyuser in legacyusers:
            new_user = self._transform.transform_user(
                legacyuser,
                self._authzName
            )
            self._dbutil.insert_new_user(new_user)
            legacy_ids_map.append([
                new_user['legacy_id'], new_user['user_id']
            ])

    def transform_groups(self, legacy_ids_map):
        legacygroups = self._dbutil.get_legacy_groups(self._domain)

        for legacygroup in legacygroups:
            new_group = self._transform.transform_group(
                legacygroup,
                self._authzName,
            )
            self._dbutil.insert_new_group(new_group)
            legacy_ids_map.append([
                new_group['legacy_id'], new_group['id']
            ])

    def transform_permissions(self, idsmap):
        self._dbutil.insert_new_perms(idsmap)


class AAAProfile(object):

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
        try:
            with open(
                '%s%s' % (self._files['authzFile'], self._TMP_SUFFIX),
                'w'
            ) as f:
                f.write(
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
                f.write(
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
                f.write(
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
            for f in self._files.values():
                os.rename('%s%s' % (f, self._TMP_SUFFIX), f)
        finally:
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


def main():
    args = parse_args()

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
        dbUtils = DBUtils(
            statement=statement,
            optionDecrypt=OptionDecrypt(prefix=args.prefix),
        )
        user_name, user_id, password = dbUtils.get_user_and_password_for_domain(args.domain)
        transform = Transform()
        transform.connect(user_name, password, args.domain)
        transform.obtain_namespaces()
        user_dn = transform.get_user_dn(user_id)

        aaaprofile = AAAProfile(
            profile=args.profile,
            authnName=args.authnName,
            authzName=args.authzName,
            user=user_dn,
            password=password,
            domain=args.domain,
        )
        aaaprofile.checkExisting()

        legacy_ids_map = []
        transform2 = Transform2(
            dbutil=dbUtils,
            transform=transform,
            domain=args.domain,
            authzName=args.authzName,
        )
        transform2.transform_users(legacy_ids_map)
        transform2.transform_groups(legacy_ids_map)
        transform2.transform_permissions(legacy_ids_map)

        aaaprofile.save()


if __name__ == "__main__":
    main()


# vim: expandtab tabstop=4 shiftwidth=4
