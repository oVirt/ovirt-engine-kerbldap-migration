import logging
import os
import re
import sys


try:
    import argparse
except ImportError:
    raise RuntimeError('Please install python-argparse')


from ..common import config
from ..common import utils


class AAADAO(utils.Base):

    def __init__(self, statement):
        self._statement = statement

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

    def _updateColumn(self, table, value, oldValue):
        self._statement.execute(
            statement="""
                update {table} set
                    domain = %(value)s
                where
                    domain = %(oldValue)s
            """.format(
                table=table,
            ),
            args=dict(
                value=value,
                oldValue=oldValue,
            ),
        )

    def update(self, value, oldValue):
        self._updateColumn('users', value, oldValue)
        self._updateColumn('ad_groups', value, oldValue)


class RollbackError(RuntimeError):
    pass


def parse_args():
    parser = argparse.ArgumentParser(
        prog='%s-authz-rename' % config.PACKAGE_NAME,
        description=(
            'Overrired current authz with new authz.'
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
        '--authz-name',
        dest='authzName',
        required=True,
        metavar='NAME',
        help='name of authz you want to rename',
    )
    parser.add_argument(
        '--new-name',
        dest='newName',
        required=True,
        metavar='NAME',
        help='new name of authz extension',
    )

    args = parser.parse_args(sys.argv[1:])

    return args


def overrideAuthz(args, engine):

    AUTHZ_MATCHER = re.compile(
        flags=re.MULTILINE | re.VERBOSE,
        pattern=r"""
            ^
            \s*
            (?P<key>
                (
                    ovirt\.engine\.aaa\.authn\.authz\.plugin
                    |
                    ovirt\.engine\.extension\.name
                )
            )
            \s*
            =
            \s*
            (?P<value>{authzName})
            \s*
            $
        """.format(
            authzName=re.escape(args.authzName),
        ),
    )

    logger = logging.getLogger(utils.Base.LOG_PREFIX)

    logger.info('Connecting to database')
    statement = engine.getStatement()

    with utils.FileTransaction() as filetransaction:
        with statement:
            aaadao = AAADAO(statement)

            logger.info('Sanity checks')
            if aaadao.isAuthzExists(args.newName):
                raise RuntimeError(
                    "User/Group from domain '%s' exists in database" % (
                        args.newName
                    )
                )

            logger.info(
                'Updating users/groups from %s to %s',
                args.authzName,
                args.newName,
            )

            updated = False
            for dname, dirs, files in os.walk(
                os.path.join(
                    engine.prefix,
                    'etc/ovirt-engine/extensions.d',
                )
            ):
                for fname in files:
                    fpath = os.path.join(dname, fname)
                    with open(fpath, 'r') as f:
                        content = f.read()
                    newcontent = ""
                    last = 0
                    for x in AUTHZ_MATCHER.finditer(content):
                        newcontent += x.string[last:x.start('key')]
                        newcontent += '%s = %s' % (
                            x.group('key'), args.newName
                        )
                        last = x.end('value')
                    newcontent += content[last:]
                    if newcontent != content:
                        with open(
                            filetransaction.getFileName(fpath),
                            'w'
                        ) as f:
                            os.chmod(f.name, 0o644)
                            f.write(newcontent)
                        aaadao.update(
                            args.authzName,
                            args.newName
                        )
                        updated = True

            if not updated:
                raise RuntimeError('Authz %s was not found.' % args.authzName)

            logger.info('Authz was successfully renamed to %s', args.newName)

            if not args.apply:
                raise RollbackError(
                    'Apply parameter was not specified rolling back'
                )


def main():
    args = parse_args()
    utils.setupLogger(log=args.log, debug=args.debug)
    logger = logging.getLogger(utils.Base.LOG_PREFIX)
    logger.info(
        'authz-rename: %s-%s (%s)',
        config.PACKAGE_NAME,
        config.PACKAGE_VERSION,
        config.LOCAL_VERSION
    ),
    logger.debug('Arguments: %s', args)

    engine = utils.Engine(prefix=args.prefix)
    engine.setupEnvironment()

    ret = 1
    try:
        overrideAuthz(args=args, engine=engine)
        ret = 0
    except RollbackError as e:
        logger.warning('%s', e)
    except Exception as e:
        logger.error("Can't override authz configuration: %s", e)
        logger.debug('Exception', exc_info=True)
    return ret


if __name__ == '__main__':
    os.umask(0o022)
    sys.exit(main())


# vim: expandtab tabstop=4 shiftwidth=4
