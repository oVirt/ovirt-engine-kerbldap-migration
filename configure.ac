AC_PREREQ(2.60)

define([VERSION_MAJOR], [1])
define([VERSION_MINOR], [0])
define([VERSION_FIX], [0])
define([VERSION_NUMBER], VERSION_MAJOR[.]VERSION_MINOR[.]VERSION_FIX)
define([VERSION_SUFFIX], [_master])

AC_INIT([ovirt-engine-kerbldap-migration], VERSION_NUMBER[]VERSION_SUFFIX)
PACKAGE_RPM_VERSION="VERSION_NUMBER"
PACKAGE_RPM_RELEASE="0.0.$(echo VERSION_SUFFIX | sed 's/^_//')"
PACKAGE_MAVEN_VERSION="VERSION_MAJOR.VERSION_MINOR.0$(echo VERSION_SUFFIX | sed 's/^_/-/')"
AC_SUBST([PACKAGE_RPM_VERSION])
AC_SUBST([PACKAGE_RPM_RELEASE])
AC_SUBST([PACKAGE_MAVEN_VERSION])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_SRCDIR([ovirt_engine_kerbldap_migration/common/utils.py])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([tar-pax])

AC_ARG_ENABLE(
	[python-syntax-check],
	[AS_HELP_STRING([--disable-python-syntax-check], [disable python syntax check @<:@default=enabled@:>@])],
	,
	[enable_python_syntax_check="yes"]
)

AC_ARG_WITH(
	[local-version],
	[AS_HELP_STRING([--with-local-version], [local version to use])],
	[LOCAL_VERSION="${withval}"],
	[LOCAL_VERSION=""]
)

AC_PROG_INSTALL
AC_PROG_SED
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_LN_S

AC_ARG_VAR([PYFLAKES], [path to pyflakes utility])
AC_CHECK_PROGS([PYFLAKES], [pyflakes])
AC_ARG_VAR([PEP8], [path to pep8 utility])
AC_CHECK_PROGS([PEP8], [pep8])

AM_PATH_PYTHON([2.6],, [AC_MSG_ERROR([Cannot find python])])

mypythonlibdir="\$(pythondir)/ovirt_engine_kerbldap_migration"
AC_SUBST([mypythonlibdir])
AC_SUBST([LOCAL_VERSION])
AM_CONDITIONAL([PYTHON_SYNTAX_CHECK], [test "${enable_python_syntax_check}" = "yes"])

AC_CONFIG_FILES([
	Makefile
	ovirt-engine-kerbldap-migration.spec
	ovirt_engine_kerbldap_migration/Makefile
	ovirt_engine_kerbldap_migration/authz_rename/Makefile
	ovirt_engine_kerbldap_migration/common/Makefile
	ovirt_engine_kerbldap_migration/common/config.py
	ovirt_engine_kerbldap_migration/tool/Makefile
])
AC_CONFIG_FILES([ovirt-engine-kerbldap-migration-spawn.sh], [chmod a+x ovirt-engine-kerbldap-migration-spawn.sh])
AC_OUTPUT
