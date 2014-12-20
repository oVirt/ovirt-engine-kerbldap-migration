#!/usr/bin/env python
import sys
import ldap
import psycopg2
import psycopg2.extras
import argparse
import uuid
import base64


def parse_args():
    parser = argparse.ArgumentParser(
        description='Transfer legacy users/groups with permissions into new extension api.'
    )
    parser.add_argument(
        '--host',
        default='localhost',
        help='host where database is running (default: localhost)'
    )
    parser.add_argument(
        '--dbname',
        default='engine',
        help='database name (default: engine)'
    )
    parser.add_argument(
        '--port',
        default='5432',
        help='port of database (default: 5432)'
    )
    parser.add_argument(
        '--dbuser',
        default='postgres',
        help='database user (default: postgres)'
    )
    parser.add_argument(
        '--dbpassword',
        help='database password (default: empty)'
    )
    parser.add_argument(
        '--legacydomain',
        help='legacy domain name'
    )
    parser.add_argument(
        '--newdomain',
        help='new domain name'
    )
    parser.add_argument(
        '--ldapuser',
        help='ldap user to bind with'
    )
    parser.add_argument(
        '--ldappassword',
        help='ldap user password'
    )
    args = parser.parse_args(sys.argv[1:])
    if not (args.legacydomain and args.newdomain and args.ldappassword and args.ldapuser):
        parser.error(
            'Domains need to be specified, add --legacydomain, --newdomain, --ldapuser and --ldappassword'
        )

    return args


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


class DBUtils(object):

    @staticmethod
    def get_legacy_users(db_connection, legacydomain):
        """
        :param db_connection:
        :param legacydomain:
        :return:
        """
        db_connection._cursor.execute("SELECT * FROM users WHERE domain = '%s'" % legacydomain)
        users = db_connection._cursor.fetchall()

        return [User(user) for user in users]

    @staticmethod
    def get_legacy_groups(db_connection, legacydomain):
        db_connection._cursor.execute("SELECT * FROM ad_groups WHERE domain = '%s'" % legacydomain)
        groups = db_connection._cursor.fetchall()

        return [Group(group) for group in groups]

    @staticmethod
    def insert_new_perm(db_connection, legacy_id, new_id):
        db_connection._cursor.execute("SELECT * FROM permissions WHERE ad_element_id = '%s'" % legacy_id)
        permission = db_connection._cursor.fetchall()[0]

        insert_query = "INSERT INTO permissions VALUES ('%s', '%s', '%s', '%s', '%s')"
        db_connection._cursor.execute(
            insert_query % (
                uuid.uuid4(),
                permission['role_id'],
                new_id,
                permission['object_id'],
                permission['object_type_id']
            )
        )

    @staticmethod
    def insert_new_perms(db_connection, useridsmap):
        for userid_map in useridsmap:
            DBUtils.insert_new_perm(
                db_connection,
                userid_map[0],
                userid_map[1]
            )
        db_connection._conn.commit()

    @staticmethod
    def insert_new_user(db_connection, user):
        """
        :param db_connection:
        :param user:
        :return:
        """
        insert_query = """
        INSERT INTO users VALUES (
        '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
        '%s', %s, '%s', '%s', '%s', '%s', '%s', '%s'
        )"""
        db_connection._cursor.execute(
            insert_query % (user.user_id, user.name, user.surname, user.domain,
                            user.username, user.groups, user.department,
                            user.role, user.email, user.note,
                            user.last_admin_check_status, user.group_ids,
                            user.external_id, user.active, user._create_date,
                            user._update_date, user.namespace)
        )
        db_connection._conn.commit()

    @staticmethod
    def insert_new_group(db_connection, group):
        insert_query = "INSERT INTO ad_groups VALUES ('%s', '%s', '%s', '%s', '%s', '%s')"
        db_connection._cursor.execute(
            insert_query % (
                group.id, group.name, group.domain, group.distinguishedname,
                group.external_id, group.namespace
            )
        )
        db_connection._conn.commit()


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
        self.ad = ADLDAP()
        self.ad.connect(user, password, domain)

    def obtain_namespaces(self):
        self.namespaces = self.ad.get_namespaces()

    def transform_group(self, legacygroup, newdomain):
        legacygroup.legacy_id = legacygroup.id
        legacygroup.id = uuid.uuid4()
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
        legacyuser.user_id = uuid.uuid4()
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


class DBConnection(object):
    _cursor = None
    _conn = None
    instance = None

    def __new__(cls, args):
        if DBConnection.instance is None:
            DBConnection.instance = object.__new__(cls)

            if not DBConnection.instance._cursor:
                DBConnection.instance._conn = psycopg2.connect(
                    database=args.dbname,
                    user=args.dbuser,
                    password=args.dbpassword,
                    host=args.host,
                    port=args.port
                )
                DBConnection.instance._cursor = DBConnection.instance._conn.cursor(
                    cursor_factory=psycopg2.extras.DictCursor
                )
        return DBConnection.instance

    def close(cls):
        if cls._cursor:
            cls._cursor.close()
        if cls._conn:
            cls._conn.close()


def transform_users(dbconn, transform, args, legacy_ids_map):
    legacyusers = DBUtils.get_legacy_users(dbconn, args.legacydomain)

    for legacyuser in legacyusers:
        new_user = transform.transform_user(legacyuser, args.newdomain)
        DBUtils.insert_new_user(dbconn, new_user)
        legacy_ids_map.append([new_user.legacy_id, new_user.user_id])


def transform_groups(dbconn, transform, args, legacy_ids_map):
    legacygroups = DBUtils.get_legacy_groups(dbconn, args.legacydomain)

    for legacygroup in legacygroups:
        new_group = transform.transform_group(legacygroup, args.newdomain)
        DBUtils.insert_new_group(dbconn, new_group)
        legacy_ids_map.append([new_group.legacy_id, new_group.id])


def transform_permissions(dbconn, idsmap):
    DBUtils.insert_new_perms(dbconn, idsmap)


def main(args):
    dbconn = DBConnection(args)
    transform = Transform()
    transform.connect(args.ldapuser, args.ldappassword, args.legacydomain)
    transform.obtain_namespaces()

    legacy_ids_map = []
    transform_users(dbconn, transform, args, legacy_ids_map)
    transform_groups(dbconn, transform, args, legacy_ids_map)
    transform_permissions(dbconn, legacy_ids_map)

    dbconn.close()


if __name__ == "__main__":
    cmd_args = parse_args()
    main(cmd_args)

