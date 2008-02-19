Name: hipl
Version: 1.0.3
Release: 1
Summary: HIP IPsec key management and mobility daemon.
URL: http://infrahip.hiit.fi/hipl/
Source: http://infrahip.hiit.fi/hipl/release/sources/%{version}/hipl-%{version}.tar.gz
Packager: hipl-dev@freelists.org
Vendor: InfraHIP
License: GPL
Group: System Environment/Kernel
Requires: openssl gtk2 libxml2 glib2 iptables-devel
BuildRequires: openssl-devel gtk2-devel libxml2-devel glib2-devel iptables-devel
ExclusiveOS: linux
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Prefix: /usr

%description

Host Identity Protocol (HIP) provides cryptographic authentication to
between hosts and secure communications using IPsec. HIP protocol
extensions support also mobility and multihoming, and traversal of NATs.

HIP for Linux (HIPL) is an implementation of a HIP implementation that
consists of the key and mobility management daemon. It includes also
other related tools and test software.

%prep
%setup

# Note: in subsequent releases me may want to use --disable-debugging
%build
%configure
make -C doc all

# Currently we are not going to install all includes and test software.
# As a consequence, we need to tell rpmbuild that we don't want to package
# everything and need the following two lines. In fact, the build fails
# without them). However, you might want to uncomment the lines temporarily
# before building the final release just to check that you have not discarded
# any essential files.
#
#%define _unpackaged_files_terminate_build 0
#%define _missing_doc_files_terminate_build 0

%install
rm -rf %{buildroot}
install -d %{buildroot}/%{prefix}/bin
install -d %{buildroot}/%{prefix}/sbin
install -d %{buildroot}/%{prefix}/lib
install -d %{buildroot}/doc
install -d %{buildroot}/etc/rc.d/init.d
make DESTDIR=%{buildroot} install
install -m 644 doc/HOWTO.txt %{buildroot}/doc
install -m 700 test/packaging/rh-init.d-hipd %{buildroot}/etc/rc.d/init.d/hipd

%pre

%post
/sbin/chkconfig --add hipd
/sbin/service hipd start

%preun
/sbin/service hipd stop
/sbin/chkconfig --del hipd

%postun

%clean
rm -rf %{buildroot}

# Note: we are not distributing everything from test directory, just essentials

# create subpackage
# list of files with the name of subpackage

%package lib
Summary: library files
Group: System Environment/Kernel
%description lib
%files	lib 
%{_libdir}/*

%package core
Summary: core files
Group: System Environment/Kernel
%description core
%files	core
%{prefix}/sbin/hipconf
%{prefix}/sbin/hipd
%{prefix}/bin/hipsetup
%config /etc/rc.d/init.d/hipd

%package agent
Summary: agent files
Group: System Environment/Kernel
%description agent
%files	agent
%{prefix}/bin/hipagent
%config /etc/rc.d/init.d/hipd

%package firewall
Summary: firewall files
Group: System Environment/Kernel
%description firewall
%files  firewall
%{prefix}/sbin/firewall

%package doc
Summary: doc files
Group: System Environment/Kernel
%description doc
%files  doc
%doc doc/HOWTO.txt doc/howto-html

%package test
Summary: test files
Group: System Environment/Kernel
%description test
%files	test
%{prefix}/bin/conntest-client
%{prefix}/bin/conntest-client-gai
%{prefix}/bin/conntest-client-native
%{prefix}/bin/conntest-client-native-user-key
%{prefix}/bin/conntest-server
%{prefix}/bin/conntest-server-native

%changelog
* Tue May 9 2006 Miika Komu <miika@iki.fi>
- init.d script, buildroot
* Mon May 6 2006 Miika Komu <miika@iki.fi>
- Minor changes. Works, finally!
* Fri May 5 2006 Miika Komu <miika@iki.fi>
- Renamed to hipl.spec (original was from Mika) and modularized
* Tue Feb 14 2006 Miika Komu <miika@iki.fi>
- added changelog

