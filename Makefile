# Copyright (C) 2004-2009  Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) 1998-2002  Internet Software Consortium.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# $Id: Makefile.in,v 1.58 2009/11/26 20:52:44 marka Exp $

srcdir =	.

top_srcdir =	.

VERSION=9.7.1-P2

SUBDIRS =	make lib bin doc 
TARGETS =

MANPAGES =	isc-config.sh.1

HTMLPAGES =	isc-config.sh.html

MANOBJS =	${MANPAGES} ${HTMLPAGES}

# Copyright (C) 2004-2009  Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) 1998-2003  Internet Software Consortium.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# $Id: rules.in,v 1.68 2009/09/01 18:40:25 jinmei Exp $

###
### Common Makefile rules for BIND 9.
###

###
### Paths
###
### Note: paths that vary by Makefile MUST NOT be listed
### here, or they won't get expanded correctly.

prefix =	/usr/local
exec_prefix =	${prefix}
bindir =	${exec_prefix}/bin
sbindir =	${exec_prefix}/sbin
includedir =	${prefix}/include
libdir =	${exec_prefix}/lib
sysconfdir =	/etc
localstatedir =	/var
mandir =	${datarootdir}/man
datarootdir =   ${prefix}/share
export_libdir =	${exec_prefix}/lib/bind9/
export_includedir = ${prefix}/include/bind9/

DESTDIR =



top_builddir =	/home/guillaume/github/bind-9.7.1-P2

###
### All
###
### Makefile may define:
###	TARGETS

all: subdirs ${TARGETS}

###
### Subdirectories
###
### Makefile may define:
###	SUBDIRS

ALL_SUBDIRS = ${SUBDIRS} nulldir

#
# We use a single-colon rule so that additional dependencies of
# subdirectories can be specified after the inclusion of this file.
# The "depend" target is treated the same way.
#
subdirs:
	@for i in ${ALL_SUBDIRS}; do \
		if [ "$$i" != "nulldir" -a -d $$i ]; then \
			echo "making all in `pwd`/$$i"; \
			(cd $$i; ${MAKE} ${MAKEDEFS} DESTDIR="${DESTDIR}" all) || exit 1; \
		fi; \
	done

install:: all

install clean distclean maintainer-clean doc docclean man manclean::
	@for i in ${ALL_SUBDIRS}; do \
		if [ "$$i" != "nulldir" -a -d $$i ]; then \
			echo "making $@ in `pwd`/$$i"; \
			(cd $$i; ${MAKE} ${MAKEDEFS} DESTDIR="${DESTDIR}" $@) || exit 1; \
		fi; \
	done

###
### C Programs
###
### Makefile must define
###	CC
### Makefile may define
###	CFLAGS
###	LDFLAGS
###	CINCLUDES
###	CDEFINES
###	CWARNINGS
### User may define externally
###     EXT_CFLAGS

CC = 		gcc
CFLAGS =	-g -O2 -I/usr/include/libxml2
LDFLAGS =	
STD_CINCLUDES =	
STD_CDEFINES =	 -D_GNU_SOURCE
STD_CWARNINGS =	 -W -Wall -Wmissing-prototypes -Wcast-qual -Wwrite-strings -Wformat -Wpointer-arith -fno-strict-aliasing

BUILD_CC = gcc
BUILD_CFLAGS = -g -O2 -I/usr/include/libxml2
BUILD_CPPFLAGS =  -D_GNU_SOURCE 
BUILD_LDFLAGS = 
BUILD_LIBS = -lcap  -lxml2

.SUFFIXES:
.SUFFIXES: .c .o

ALWAYS_INCLUDES = -I${top_builddir}
ALWAYS_DEFINES = 
ALWAYS_WARNINGS =

ALL_CPPFLAGS = \
	${ALWAYS_INCLUDES} ${CINCLUDES} ${STD_CINCLUDES} \
	${ALWAYS_DEFINES} ${CDEFINES} ${STD_CDEFINES}

ALL_CFLAGS = ${EXT_CFLAGS} ${ALL_CPPFLAGS} ${CFLAGS} \
	${ALWAYS_WARNINGS} ${STD_CWARNINGS} ${CWARNINGS}

.c.o:
	${LIBTOOL_MODE_COMPILE} ${CC} ${ALL_CFLAGS} -c $<

SHELL = /bin/bash
LIBTOOL = 
LIBTOOL_MODE_COMPILE = ${LIBTOOL} 
LIBTOOL_MODE_INSTALL = ${LIBTOOL} 
LIBTOOL_MODE_LINK = ${LIBTOOL} 
PURIFY = 

MKDEP = ${SHELL} ${top_builddir}/make/mkdep

###
### This is a template compound command to build an executable binary with
### an internal symbol table.
### This process is tricky.  We first link all objects including a tentative
### empty symbol table, then get a tentative list of symbols from the resulting
### binary ($@tmp0).  Next, we re-link all objects, but this time with the
### symbol table just created ($tmp@1).  The set of symbols should be the same,
### but the corresponding addresses would be changed due to the difference on
### the size of symbol tables.  So we create the symbol table and re-create the
### objects once again.  Finally, we check the symbol table embedded in the
### final binaryis consistent with the binary itself; otherwise the process is
### terminated.
###
### To minimize the overhead of creating symbol tables, the autoconf switch
### --enable-symtable takes an argument so that the symbol table can be created
### on a per application basis: unless the argument is set to "all", the symbol
### table is created only when a shell (environment) variable "MAKE_SYMTABLE" is
### set to a non-null value in the rule to build the executable binary.
###
### Each Makefile.in that uses this macro is expected to define "LIBS" and
### "NOSYMLIBS"; the former includes libisc with an empty symbol table, and
### the latter includes libisc without the definition of a symbol table.
### The rule to make the executable binary will look like this
### binary: ${OBJS}
###     #export MAKE_SYMTABLE="yes"; \  <- enable if symtable is always needed
###	export BASEOBJS="${OBJS}"; \
###	${FINALBUILDCMD}
###
### Normally, ${LIBS} includes all necessary libraries to build the binary;
### there are some exceptions however, where the rule lists some of the
### necessary libraries explicitly in addition to (or instead of) ${LIBS},
### like this:
### binary: ${OBJS}
###     cc -o $@ ${OBJS} ${OTHERLIB1} ${OTHERLIB2} ${lIBS}
### in order to modify such a rule to use this compound command, a separate
### variable "LIBS0" should be deinfed for the explicitly listed libraries,
### while making sure ${LIBS} still includes libisc.  So the above rule would
### be modified as follows:
### binary: ${OBJS}
###	export BASEOBJS="${OBJS}"; \
###	export LIBS0="${OTHERLIB1} ${OTHERLIB2}"; \
###     ${FINALBUILDCMD}
### See bin/check/Makefile.in for a complete example of the use of LIBS0.
###
FINALBUILDCMD = if [ X"${MKSYMTBL_PROGRAM}" = X -o X"$${MAKE_SYMTABLE:-${ALWAYS_MAKE_SYMTABLE}}" = X ] ; then \
		${LIBTOOL_MODE_LINK} ${PURIFY} ${CC} ${CFLAGS} ${LDFLAGS} \
		-o $@ $${BASEOBJS} $${LIBS0} ${LIBS}; \
	else \
		rm -f $@tmp0; \
		${LIBTOOL_MODE_LINK} ${PURIFY} ${CC} ${CFLAGS} ${LDFLAGS} \
		-o $@tmp0 $${BASEOBJS} $${LIBS0} ${LIBS} || exit 1; \
		rm -f $@-symtbl.c $@-symtbl.o; \
		${MKSYMTBL_PROGRAM} ${top_srcdir}/util/mksymtbl.pl \
		-o $@-symtbl.c $@tmp0 || exit 1; \
		$(MAKE) $@-symtbl.o || exit 1; \
		rm -f $@tmp1; \
		${LIBTOOL_MODE_LINK} ${PURIFY} ${CC} ${CFLAGS} ${LDFLAGS} \
		-o $@tmp1 $${BASEOBJS} $@-symtbl.o $${LIBS0} ${NOSYMLIBS} || exit 1; \
		rm -f $@-symtbl.c $@-symtbl.o; \
		${MKSYMTBL_PROGRAM} ${top_srcdir}/util/mksymtbl.pl \
		-o $@-symtbl.c $@tmp1 || exit 1; \
		$(MAKE) $@-symtbl.o || exit 1; \
		${LIBTOOL_MODE_LINK} ${PURIFY} ${CC} ${CFLAGS} ${LDFLAGS} \
		-o $@tmp2 $${BASEOBJS} $@-symtbl.o $${LIBS0} ${NOSYMLIBS}; \
		${MKSYMTBL_PROGRAM} ${top_srcdir}/util/mksymtbl.pl \
		-o $@-symtbl2.c $@tmp2; \
		diff $@-symtbl.c $@-symtbl2.c || exit 1;\
		mv $@tmp2 $@; \
		rm -f $@tmp0 $@tmp1 $@tmp2 $@-symtbl2.c; \
	fi

cleandir: distclean
superclean: maintainer-clean

clean distclean maintainer-clean::
	rm -f *.o *.o *.lo *.la core *.core *-symtbl.c *tmp0 *tmp1 *tmp2
	rm -rf .depend .libs

distclean maintainer-clean::
	rm -f Makefile

depend:
	@for i in ${ALL_SUBDIRS}; do \
		if [ "$$i" != "nulldir" -a -d $$i ]; then \
			echo "making depend in `pwd`/$$i"; \
			(cd $$i; ${MAKE} ${MAKEDEFS} DESTDIR="${DESTDIR}" $@) || exit 1; \
		fi; \
	done
	@if [ X"${VPATH}" != X ] ; then \
		if [ X"${SRCS}" != X -a X"${PSRCS}" != X ] ; then \
			echo ${MKDEP} -vpath ${VPATH} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			${MKDEP} -vpath ${VPATH} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			echo ${MKDEP} -vpath ${VPATH} -ap ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${MKDEP} -vpath ${VPATH} -ap ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${DEPENDEXTRA} \
		elif [ X"${SRCS}" != X ] ; then \
			echo ${MKDEP} -vpath ${VPATH} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			${MKDEP} -vpath ${VPATH} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			${DEPENDEXTRA} \
		elif [ X"${PSRCS}" != X ] ; then \
			echo ${MKDEP} -vpath ${VPATH} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${MKDEP} -vpath ${VPATH} -p ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${DEPENDEXTRA} \
		fi \
	else \
		if [ X"${SRCS}" != X -a X"${PSRCS}" != X ] ; then \
			echo ${MKDEP} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			${MKDEP} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			echo ${MKDEP} -ap ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${MKDEP} -ap ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${DEPENDEXTRA} \
		elif [ X"${SRCS}" != X ] ; then \
			echo ${MKDEP} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			${MKDEP} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			${DEPENDEXTRA} \
		elif [ X"${PSRCS}" != X ] ; then \
			echo ${MKDEP} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${MKDEP} -p ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${DEPENDEXTRA} \
		fi \
	fi

FORCE:

###
### Libraries
###

AR =		/usr/bin/ar
ARFLAGS =	cruv
RANLIB =	ranlib

###
### Installation
###

INSTALL =		/usr/bin/install -c
INSTALL_PROGRAM =	${INSTALL}
LINK_PROGRAM =		ln -s
INSTALL_SCRIPT =	${INSTALL}
INSTALL_DATA =		${INSTALL} -m 644

###
### Programs used when generating documentation.  It's ok for these
### not to exist when not generating documentation.
###

XSLTPROC =		/usr/bin/xsltproc --novalid --xinclude --nonet
PERL =			/usr/bin/perl
LATEX =			latex
PDFLATEX =		pdflatex
W3M =			/usr/bin/w3m

###
### Script language program used to create internal symbol tables
###
MKSYMTBL_PROGRAM =	/usr/bin/perl

###
### Switch to create internal symbol table selectively
###
ALWAYS_MAKE_SYMTABLE =	

###
### DocBook -> HTML
### DocBook -> man page
###

.SUFFIXES: .docbook .html .1 .2 .3 .4 .5 .6 .7 .8

.docbook.html:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-docbook-html.xsl $<

.docbook.1:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.2:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.3:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.4:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.5:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.6:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.7:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.8:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

distclean::
	rm -f config.cache config.h config.log config.status TAGS
	rm -f libtool isc-config.sh configure.lineno
	rm -f util/conf.sh docutil/docbook2man-wrapper.sh

# XXX we should clean libtool stuff too.  Only do this after we add rules
# to make it.
maintainer-clean::
	rm -f configure

docclean manclean maintainer-clean::
	rm -f ${MANOBJS}

doc man:: ${MANOBJS}

installdirs:
	$(SHELL) ${top_srcdir}/mkinstalldirs ${DESTDIR}${bindir} \
	${DESTDIR}${localstatedir}/run ${DESTDIR}${sysconfdir}
	$(SHELL) ${top_srcdir}/mkinstalldirs ${DESTDIR}${mandir}/man1

install:: isc-config.sh installdirs
	${INSTALL_SCRIPT} isc-config.sh ${DESTDIR}${bindir}
	${INSTALL_DATA} ${top_srcdir}/isc-config.sh.1 ${DESTDIR}${mandir}/man1
	${INSTALL_DATA} ${top_srcdir}/bind.keys ${DESTDIR}${sysconfdir}

tags:
	rm -f TAGS
	find lib bin -name "*.[ch]" -print |  -

check: test

test:
	(cd bin/tests && ${MAKE} ${MAKEDEFS} test)

FAQ: FAQ.xml
	${XSLTPROC} doc/xsl/isc-docbook-text.xsl FAQ.xml | \
	LC_ALL=C ${W3M} -T text/html -dump -cols 72 >$@.tmp
	mv $@.tmp $@

clean::
	rm -f FAQ.tmp
