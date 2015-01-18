include $(top_srcdir)/build/python.inc

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

mymodulelibdir=$(mypythonlibdir)/common

dist_mymodulelib_PYTHON = \
	__init__.py \
	config.py \
	utils.py \
	$(NULL)

clean-local: \
	python-clean \
	$(NULL)

all-local: \
	$(DISTFILES) \
	python-syntax-check \
	$(NULL)
