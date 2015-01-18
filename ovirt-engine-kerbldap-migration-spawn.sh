#!/bin/sh

if [ -e "$(dirname $0)/ovirt_engine_kerbldap_migration" ]; then
	PYTHONPATH="$(dirname $0):${PYTHONPATH}"
fi

# TODO remove '.__main__' when python-2.6 gone
exec "${PYTHON:-python}" \
	-m ovirt_engine_kerbldap_migration.$(
		basename "$0" |
		sed \
			-e 's/ovirt-engine-kerbldap-migration-//' \
			-e 's/-/_/g' \
			-e 's/\.sh//'
		).__main__ "${@}"
