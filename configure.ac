# virt-what
# Copyright (C) 2008-2018 Red Hat Inc.
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

AC_INIT([virt-what],[1.20])
AM_INIT_AUTOMAKE([foreign])

dnl Check for basic C environment.
AC_PROG_CC_STDC
AC_PROG_INSTALL
AC_PROG_CPP

AC_C_PROTOTYPES
test "x$U" != "x" && AC_MSG_ERROR([Compiler not ANSI compliant])

AM_PROG_CC_C_O

dnl Architecture we are compiling for.
AC_CANONICAL_HOST
AM_CONDITIONAL([HOST_CPU_IA64], [ test "x$host_cpu" = "xia64" ])

dnl List of tests.
tests="\
	aws-baremetal-x86 \
	aws-kvm-arm \
	aws-kvm-x86 \
	aws-xen-x86 \
	baremetal \
	bhyve \
	docker \
	esx4.1 \
	hyperv \
	kvm \
	kvm-explicit-cpu \
	ldoms \
	linux-vserver \
	lkvm \
	lkvm-arm \
	lx86 \
	lxc \
	parallels-desktop \
	ppc64-baremetal \
	ppc64-kvm \
	ppc64-lpar-dedicated \
	ppc64-lpar-shared \
	qemu \
	qemu-arm \
	qemu-smbios \
	qemu-smbios-kvm \
	rhel5-xen-dom0 \
	rhel5-xen-domU-hvm \
	rhel5-xen-domU-hvm-ia64 \
	rhel5-xen-domU-pv \
	rhev \
	vmm \
	xen-arm \
	zvm \
        "
AC_SUBST([tests])

dnl Produce output files.
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([virt-what],[chmod +x virt-what])
AC_CONFIG_FILES([Makefile
                 tests/Makefile
	         tests/aws-baremetal-x86/Makefile
	         tests/aws-kvm-arm/Makefile
	         tests/aws-kvm-x86/Makefile
	         tests/aws-xen-x86/Makefile
	         tests/baremetal/Makefile
	         tests/bhyve/Makefile
	         tests/docker/Makefile
	         tests/esx4.1/Makefile
	         tests/hyperv/Makefile
	         tests/kvm/Makefile
	         tests/kvm-explicit-cpu/Makefile
	         tests/ldoms/Makefile
	         tests/linux-vserver/Makefile
	         tests/lkvm/Makefile
	         tests/lkvm-arm/Makefile
	         tests/lx86/Makefile
	         tests/lxc/Makefile
	         tests/parallels-desktop/Makefile
	         tests/ppc64-baremetal/Makefile
	         tests/ppc64-kvm/Makefile
	         tests/ppc64-lpar-dedicated/Makefile
	         tests/ppc64-lpar-shared/Makefile
	         tests/qemu/Makefile
	         tests/qemu-arm/Makefile
	         tests/qemu-smbios/Makefile
	         tests/qemu-smbios-kvm/Makefile
	         tests/rhel5-xen-dom0/Makefile
	         tests/rhel5-xen-domU-hvm/Makefile
	         tests/rhel5-xen-domU-hvm-ia64/Makefile
	         tests/rhel5-xen-domU-pv/Makefile
	         tests/rhev/Makefile
	         tests/vmm/Makefile
	         tests/xen-arm/Makefile
	         tests/zvm/Makefile
                 ])

AC_CHECK_PROG([POD2MAN], [pod2man], [pod2man], [false])
if test "$POD2MAN" = "false"; then
    AC_MSG_WARN([pod2man was not found.  This is needed to build man pages.])
fi
AM_CONDITIONAL([HAVE_POD2MAN], [test "$POD2MAN" != "false"])

AC_OUTPUT
