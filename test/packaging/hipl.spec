Name: hipl
Version: 1.0.3
Release: 1
Summary: HIP IPsec key management and mobility daemon.
URL: http://infrahip.hiit.fi/hipl/
Source: http://infrahip.hiit.fi/hipl/release/%{version}
Packager: hipl-dev@freelists.org
Vendor: InfraHIP
License: GPL
Group: System Environment/Kernel
Requires: openssl gtk2 libxml2 glib iptables-dev
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

%build
./configure --prefix=%{buildroot}/%{prefix} && make
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
make install
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
%files
%defattr (-, root, root)
%{prefix}/sbin/hipconf
%{prefix}/sbin/hipd
%{prefix}/sbin/firewall
%{prefix}/bin/hipsetup
%{prefix}/bin/hipagent
%{prefix}/bin/conntest-client
%{prefix}/bin/conntest-client-gai
%{prefix}/bin/conntest-client-native
%{prefix}/bin/conntest-client-native-user-key
%{prefix}/bin/conntest-server
%{prefix}/bin/conntest-server-native
%{prefix}/lib/*
%config /etc/rc.d/init.d/hipd
%doc doc/HOWTO.txt doc/howto-html

%changelog
* Tue May 9 2006 Miika Komu <miika@iki.fi>
- init.d script, buildroot
* Mon May 6 2006 Miika Komu <miika@iki.fi>
- Minor changes. Works, finally!
* Fri May 5 2006 Miika Komu <miika@iki.fi>
- Renamed to hipl.spec (original was from Mika) and modularized
* Tue Feb 14 2006 Miika Komu <miika@iki.fi>
- added changelog
