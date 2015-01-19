include $(top_srcdir)/build/python.inc

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

SUBDIRS = \
	authz_rename \
	common \
	tool \
	$(NULL)

mymodulelibdir=$(mypythonlibdir)

dist_mymodulelib_PYTHON = \
	__init__.py \
	$(NULL)

clean-local: \
	python-clean \
	$(NULL)

all-local: \
	$(DISTFILES) \
	python-syntax-check \
	$(NULL)
