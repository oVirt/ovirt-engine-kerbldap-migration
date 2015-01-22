import logging
import os
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
        return len(
            self._statement.execute(
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
            ) != 0
        )

    def _updateColumn(self, table, column, value, oldValue):
        self._statement.execute(
            statement="""
                update {table} set
                    {column} = %(value)s
                where
                    {column} = %(oldValue)s
            """.format(
                table=table,
                column=column,
            ),
            args=dict(
                value=value,
                oldValue=oldValue,
            ),
        )

    def updateUsers(self, column, value, oldValue):
        self._updateColumn('users', column, value, oldValue)

    def updateGroups(self, column, value, oldValue):
        self._updateColumn('ad_groups', column, value, oldValue)


class AAAParser(utils.Base):

    _TMP_SUFFIX = '.tmp'

    def __init__(self, aaafile):
        super(AAAParser, self).__init__()
        self.aaafile = aaafile
        self.aaafile_temp = '%s%s' % (aaafile, self._TMP_SUFFIX)

    def read(self):
        with open(self.aaafile) as f:
            self.content = f.read()

    def save(self):
        def _writelog(f, s):
            self.logger.debug("Write '%s'\n%s", f, s)
            f.write(s)

        with open(self.aaafile_temp, 'w') as f:
            _writelog(f, self.content)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.logger.debug('Commit')
            swap_file = '%s%s' % (self.aaafile_temp, self._TMP_SUFFIX)
            if os.path.exists(self.aaafile_temp):
                os.rename(self.aaafile_temp, swap_file)
                os.rename(self.aaafile, self.aaafile_temp)
                os.rename(swap_file, self.aaafile)
        else:
            self.logger.debug('Rollback')
            if os.path.exists(self.aaafile_temp):
                os.unlink(self.aaafile_temp)


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
        '--apply',
        default=False,
        action='store_true',
        help='apply settings'
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
    logger = logging.getLogger(utils.Base.LOG_PREFIX)
    logger.info('Connecting to database')

    statement = engine.getStatement()

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
            'Updating users/groups from %s to %s', args.authzName, args.newName
        )

        updated = False
        for dname, dirs, files in os.walk('/etc/ovirt-engine/extensions.d/'):
            for fname in files:
                fpath = os.path.join(dname, fname)
                with AAAParser(fpath) as aaafile:
                    aaafile.read()

                    if aaafile.content.find(args.authzName) > 0:
                        aaadao.updateUsers(
                            'domain',
                            args.authzName,
                            args.newName
                        )
                        aaadao.updateGroups(
                            'domain',
                            args.authzName,
                            args.newName
                        )
                        aaafile.content = aaafile.content.replace(
                            args.authzName,
                            args.newName
                        )
                        aaafile.save()
                        updated = True

        if not updated:
            raise RuntimeError('Authz %s was not found.' % args.authzName)
        logger.info('Authz was successfully renamed to %s', args.newName)


def main():
    args = parse_args()
    utils.setupLogger(log=args.log, debug=args.debug)
    logger = logging.getLogger(utils.Base.LOG_PREFIX)
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
    sys.exit(main())


# vim: expandtab tabstop=4 shiftwidth=4
