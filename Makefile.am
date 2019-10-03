# Makefile for virt-what
# Copyright (C) 2008-2011 Red Hat Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

AM_CPPFLAGS = -Wall

CLEANFILES = virt-what *~

EXTRA_DIST = .gitignore virt-what.in virt-what.pod

SUBDIRS = . tests

sbin_SCRIPTS = virt-what
libexec_PROGRAMS = virt-what-cpuid-helper
if HOST_CPU_IA64
libexec_PROGRAMS += virt-what-ia64-xen-rdtsc-test
endif

if HAVE_POD2MAN

CLEANFILES += virt-what.1 virt-what.txt
man_MANS = virt-what.1

virt-what.1: virt-what.pod
	pod2man -c "Virtualization Support" --release "$(PACKAGE)-$(VERSION)" \
	  $? > $@
virt-what.txt: virt-what.pod
	pod2text $? > $@

endif
