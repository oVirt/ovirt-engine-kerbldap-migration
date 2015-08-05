import mock
import os.path
import pytest

from ..common import utils
from ..tool import __main__ as tool

AAAFFILE = '{prefix}/etc/ovirt-engine/aaa/{filename}.properties'
EXTFILE = '{prefix}/etc/ovirt-engine/extensions.d/{filename}.properties'


@pytest.fixture
def adDriver():
    driver = tool.ADLDAP(
        mock.create_autospec(utils.Kerberos),
        None,
    )
    driver._bindURI = 'ldap.activedirectory.org:188'
    driver._bindPassword = '123456'
    driver._dnsDomain = 'activedirectory.org'
    driver._protocol = 'ldap'

    return driver


@pytest.fixture
def ldapDriver():
    driver = tool.OpenLDAP(
        mock.create_autospec(utils.Kerberos),
        None,
    )
    driver._bindURI = 'ldap.openldap.org:389'
    driver._bindPassword = '123456'
    driver._dnsDomain = 'openldap.org'
    driver._protocol = 'ldaps'

    return driver


def test_ad(adDriver):
    with utils.FileTransaction() as filetransaction:
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
    with utils.FileTransaction() as filetransaction:
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
