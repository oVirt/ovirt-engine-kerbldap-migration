#!/usr/bin/python
import logging
import sys

from ovirtexceptions import RollbackError
from utils import (
    Base, AAADAO, AAAParser, setupLogger, getEngineDir, getEngineStatement,
)

try:
    import argparse
except ImportError:
    raise RuntimeError('Please install python-argparse')


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            'Overrired current authz with new authz.'
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
        metavar='FILE',
        help='path to authz extension configuration',
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


def overrideAuthz(args):
    logger = logging.getLogger(Base.LOG_PREFIX)
    logger.info('Connecting to database')

    engineDir = getEngineDir(args.prefix)
    statement = getEngineStatement(engineDir, args.prefix)

    with statement:
        aaadao = AAADAO(statement)

        logger.info('Sanity checks')
        if aaadao.isDomainExists(args.newName):
            raise RuntimeError(
                "User/Group from domain '%s' exists in database" % (
                    args.newName
                )
            )

        logger.info('Updating users/groups from to %s' % (args.newName))
        with AAAParser(args.authzName) as authz:
            authz.read()
            authzName = authz.getValue('ovirt.engine.extension.name')

            # Update all users/groups with authzName to newName
            aaadao.updateUsers('domain', authzName, args.newName)
            aaadao.updateGroups('domain', authzName, args.newName)

            authz.setValue('ovirt.engine.extension.name', args.newName)
            authz.save()


def main():
    args = parse_args()
    setupLogger(log=args.log, debug=args.debug)
    logger = logging.getLogger(Base.LOG_PREFIX)
    logger.debug('Arguments: %s', args)

    ret = 1
    try:
        overrideAuthz(args)
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
