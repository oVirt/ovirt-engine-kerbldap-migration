import mock
import os.path
import pytest
import shutil
import sys

from ..authz_rename import __main__ as rename


PREFIX = '/tmp'
AUTHZ_NAME = 'myad-authz-new'
AUTHZ_NAME_NEW = 'myad-authz'
EXT_DIR = os.path.join(PREFIX, 'etc/ovirt-engine/extensions.d')
AUTHZ_FILE = os.path.join(EXT_DIR, 'myad-authz.properties')
AUTHN_FILE = os.path.join(EXT_DIR, 'myad-authn.properties')

AUTHN = (
    'ovirt.engine.extension.name = myad-authn\n'
    'ovirt.engine.extension.bindings.method = jbossmodule\n'
    'ovirt.engine.extension.binding.jbossmodule.module = '
    'org.ovirt.engine-extensions.aaa.ldap\n'
    'ovirt.engine.extension.binding.jbossmodule.class = '
    'org.ovirt.engineextensions.aaa.ldap.AuthnExtension\n'
    'ovirt.engine.extension.provides = '
    'org.ovirt.engine.api.extensions.aaa.Authn\n'
    'ovirt.engine.aaa.authn.profile.name = myad\n'
    'ovirt.engine.aaa.authn.authz.plugin = {myadauthz}\n'
    'config.profile.file.1 = ../aaa/myad.properties\n'
    .format(
        myadauthz=AUTHZ_NAME,
    )
)
AUTHZ = (
    'ovirt.engine.extension.name = {myadauthz}\n'
    'ovirt.engine.extension.bindings.method = jbossmodule\n'
    'ovirt.engine.extension.binding.jbossmodule.module = '
    'org.ovirt.engine-extensions.aaa.ldap\n'
    'ovirt.engine.extension.binding.jbossmodule.class = '
    'org.ovirt.engineextensions.aaa.ldap.AuthzExtension\n'
    'ovirt.engine.extension.provides = '
    'org.ovirt.engine.api.extensions.aaa.Authz\n'
    'config.profile.file.1 = ../aaa/myad.properties\n'
    .format(
        myadauthz=AUTHZ_NAME,
    )
)


def setup_module():
    """ Create fake configuration """
    if os.path.isdir("%s/etc" % PREFIX):
        shutil.rmtree('%s/etc' % PREFIX)

    if not os.path.exists(EXT_DIR):
        os.makedirs(EXT_DIR)

    with open(AUTHN_FILE, 'w') as authn_file:
        authn_file.write(AUTHN)

    with open(AUTHZ_FILE, 'w') as authz_file:
        authz_file.write(AUTHZ)


def teardown_module():
    if os.path.isdir("%s/etc" % PREFIX):
        shutil.rmtree('%s/etc' % PREFIX)


@pytest.fixture
def engine1():
    """ This engine impl already contains users with specified authz """
    statement = mock.MagicMock()
    statement.execute = mock.MagicMock(return_value=[1])
    statement.__exit__ = mock.MagicMock(return_value=None)

    engine = rename.utils.Engine(prefix=PREFIX)
    engine.getStatement = mock.MagicMock(return_value=statement)

    return engine


@pytest.fixture
def engine2():
    """ This engine impl already DON'T contains users with specified authz """
    statement = mock.MagicMock()
    statement.execute = mock.MagicMock(return_value=[])
    statement.__exit__ = mock.MagicMock(return_value=None)

    engine = rename.utils.Engine(prefix=PREFIX)
    engine.getStatement = mock.MagicMock(return_value=statement)

    return engine


def test_args_bad():
    sys.argv = ['very', 'bad']
    with pytest.raises(SystemExit) as err:
        rename.main()
    assert '2' == str(err.value)


def test_missing_authz():
    sys.argv = ['authz_rename', '--new-name=test']
    with pytest.raises(SystemExit) as err:
        rename.main()
    assert '2' == str(err.value)


def test_missing_newname():
    sys.argv = ['authz_rename', '--authz-name=X']
    with pytest.raises(SystemExit) as err:
        rename.main()
    assert '2' == str(err.value)


def test_args_correct():
    sys.argv = ['authz_rename', '--help']
    with pytest.raises(SystemExit) as err:
        rename.main()
    assert '0' == str(err.value)


def test_rename_with_existing_users_in_db(engine1):
    sys.argv = ['authz_rename', '--authz-name=X', '--new-name=Y']
    args = rename.parse_args()
    with pytest.raises(RuntimeError) as err:
        rename.overrideAuthz(args=args, engine=engine1)
    assert 'exists in database' in str(err)


def test_rename_with_nonexistent_authz(engine2):
    sys.argv = ['authz_rename', '--authz-name=XYZ123XYZ', '--new-name=Y']
    args = rename.parse_args()
    with pytest.raises(RuntimeError) as err:
        rename.overrideAuthz(args=args, engine=engine2)
    assert 'was not found' in str(err)


def test_rename_without_apply(engine2):
    sys.argv = ['authz_rename', '--authz-name=%s' % AUTHZ_NAME, '--new-name=Y']
    args = rename.parse_args()
    with pytest.raises(rename.RollbackError) as err:
        rename.overrideAuthz(args=args, engine=engine2)
    assert 'Apply parameter was not specified' in str(err)


def test_rename_with_apply(engine2):
    sys.argv = [
        'authz_rename',
        '--authz-name=%s' % AUTHZ_NAME,
        '--new-name=%s' % AUTHZ_NAME_NEW,
        '--apply',
    ]
    args = rename.parse_args()
    rename.overrideAuthz(args=args, engine=engine2)

    with open(AUTHZ_FILE) as f:
        AUTHZ_NAME_NEW in f.read()

    with open(AUTHN_FILE) as f:
        AUTHZ_NAME_NEW in f.read()
