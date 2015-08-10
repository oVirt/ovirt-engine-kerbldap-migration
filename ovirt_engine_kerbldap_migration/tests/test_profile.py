import mock
import os.path
import pytest
import shutil
import sys

from ..tool import __main__ as tool

AAAFFILE = '{prefix}/etc/ovirt-engine/aaa/{filename}.properties'
EXTFILE = '{prefix}/etc/ovirt-engine/extensions.d/{filename}.properties'


def teardown_module():
    if os.path.isdir("/tmp/etc"):
        shutil.rmtree('/tmp/etc')


@pytest.fixture
def adDriver():
    driver = tool.ADLDAP(
        mock.create_autospec(tool.utils.Kerberos),
        None,
    )
    driver._bindURI = 'ldap.activedirectory.org:389'
    driver._bindPassword = '123456'
    driver._dnsDomain = 'activedirectory.org'
    driver._protocol = 'ldap'
    driver._port = '389'

    return driver


@pytest.fixture
def ldapDriver():
    driver = tool.OpenLDAP(
        mock.create_autospec(tool.utils.Kerberos),
        None,
    )
    driver._bindURI = 'ldap.openldap.org:389'
    driver._bindPassword = '123456'
    driver._dnsDomain = 'openldap.org'
    driver._protocol = 'ldaps'
    driver._port = '389'

    return driver


def test_ad(adDriver):
    with tool.utils.FileTransaction() as filetransaction:
        profile = tool.AAAProfile(
            profile='activeDirectory',
            authnName='activedirectory-authn',
            authzName='activedirectory-authz',
            driver=adDriver,
            filetransaction=filetransaction,
            prefix='/tmp/',
        )
        profile.save()

    assert os.path.isfile(
        EXTFILE.format(prefix='/tmp/', filename='activedirectory-authn')
    )
    assert os.path.isfile(
        EXTFILE.format(prefix='/tmp/', filename='activedirectory-authz')
    )
    assert os.path.isfile(
        AAAFFILE.format(prefix='/tmp/', filename='activeDirectory')
    )


def test_openldap(ldapDriver):
    with tool.utils.FileTransaction() as filetransaction:
        profile = tool.AAAProfile(
            profile='profile',
            authnName='authnName',
            authzName='authzName',
            driver=ldapDriver,
            filetransaction=filetransaction,
            prefix='/tmp/',
        )
        profile.save()

    assert os.path.isfile(
        EXTFILE.format(prefix='/tmp', filename='authnName')
    )
    assert os.path.isfile(
        EXTFILE.format(prefix='/tmp', filename='authzName')
    )
    assert os.path.isfile(
        AAAFFILE.format(prefix='/tmp', filename='profile')
    )


def test_args_bad():
    sys.argv = ['very', 'bad']
    with pytest.raises(SystemExit) as err:
        tool.main()
    assert '2' == str(err.value)


def test_args_correct():
    sys.argv = ['tool', '--help']
    with pytest.raises(SystemExit) as err:
        tool.main()
    assert '0' == str(err.value)
