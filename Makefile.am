AUTOMAKE_OPTIONS = foreign 1.9
ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/py-compile \
	$(srcdir)/config.guess $(srcdir)/config.sub \
	$(srcdir)/config.rpath \
	$(srcdir)/ABOUT-NLS \
	$(srcdir)/aclocal.m4 \
	$(srcdir)/ln-sr \
	$(NULL)
CLEANFILES = \
	ovirt-engine-kerbldap-migration-authz-rename \
	ovirt-engine-kerbldap-migration-tool \
	$(NULL)

EXTRA_DIST = \
	.gitignore \
	$(NULL)

SUBDIRS = \
	ovirt_engine_kerbldap_migration \
	$(NULL)

dist_doc_DATA = \
	README.md \
	$(NULL)

dist_noinst_DATA = \
	ovirt-engine-kerbldap-migration.spec \
	$(NULL)

dist_bin_SCRIPTS = \
	ovirt-engine-kerbldap-migration-spawn.sh \
	$(NULL)

all-local:
	[ -L ovirt-engine-kerbldap-migration-authz-rename ] || ln -s ovirt-engine-kerbldap-migration-spawn.sh ovirt-engine-kerbldap-migration-authz-rename
	[ -L ovirt-engine-kerbldap-migration-tool ] || ln -s ovirt-engine-kerbldap-migration-spawn.sh ovirt-engine-kerbldap-migration-tool

install-exec-local:
	[ -r "$(DESTDIR)$(bindir)/ovirt-engine-kerbldap-migration-authz-rename" ] && rm -f "$(DESTDIR)$(bindir)/ovirt-engine-kerbldap-migration-authz-rename" || :
	[ -r "$(DESTDIR)$(bindir)/ovirt-engine-kerbldap-migration-tool" ] && rm -f "$(DESTDIR)$(bindir)/ovirt-engine-kerbldap-migration-tool" || :
	ln -s ovirt-engine-kerbldap-migration-spawn.sh "$(DESTDIR)$(bindir)/ovirt-engine-kerbldap-migration-authz-rename"
	ln -s ovirt-engine-kerbldap-migration-spawn.sh "$(DESTDIR)$(bindir)/ovirt-engine-kerbldap-migration-tool"

uninstall-local:
	[ -r "$(DESTDIR)$(bindir)/ovirt-engine-kerbldap-migration-authz-rename" ] && rm -f "$(DESTDIR)$(bindir)/ovirt-engine-kerbldap-migration-authz-rename"
	[ -r "$(DESTDIR)$(bindir)/ovirt-engine-kerbldap-migration-tool" ] && rm -f "$(DESTDIR)$(bindir)/ovirt-engine-kerbldap-migration-tool"
