include $(top_srcdir)/build/python.inc

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

mymodulelibdir=$(mypythonlibdir)/common

dist_mymodulelib_PYTHON = \
	__init__.py \
	utils.py \
	$(NULL)

nodist_mymodulelib_PYTHON = \
	config.py \
	$(NULL)

clean-local: \
	python-clean \
	$(NULL)

all-local: \
	$(DISTFILES) \
	python-syntax-check \
	$(NULL)
