import pytest
import sys

from ..authz_rename import __main__ as rename

def test_args_bad():
    sys.argv = ['very', 'bad']
    with pytest.raises(SystemExit) as err:
        rename.main()
    assert '2' == str(err.value)


def test_args_correct():
    sys.argv = ['authz_rename', '--help']
    with pytest.raises(SystemExit) as err:
        rename.main()
    assert '0' == str(err.value)
