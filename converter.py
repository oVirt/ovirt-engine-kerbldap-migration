#!/usr/bin/python
# Note you need cyrus-sasl-gssapi package
import glob
import logging
import os
import sys
import uuid

from ovirtexceptions import RollbackError
from utils import (
    Base, ADLDAP, IPALDAP, RHDSLDAP, OpenLDAP, Statement, AAADAO,
    VdcOptions, OptionDecrypt, Kerberos, AAAProfile,
)

try:
    import argparse
except ImportError:
    raise RuntimeError('Please install python-argparse')


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
        args.authzName = args.domain

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

        logger.info('Sanity checks')
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
        if args.ldapServers:
            domainEntry['ldapServers'] = args.ldapServers

        driver = DRIVERS.get(domainEntry['provider'])
        if driver is None:
            raise RuntimeError(
                "Provider '%s' is not supported" % domainEntry['provider']
            )

        driver = driver(Kerberos(args.prefix), args.domain)
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

        with AAAProfile(
            profile=args.profile,
            authnName=args.authnName,
            authzName=args.authzName,
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


if __name__ == '__main__':
    sys.exit(main())


# vim: expandtab tabstop=4 shiftwidth=4
