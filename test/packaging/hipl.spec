Name: hipl
Version: 1.0.1
Release: 1
Summary: HIP IPsec key management and mobility daemon.
URL: http://infrahip.hiit.fi/hipl/
Source: http://infrahip.hiit.fi/hipl/release/sources/%{version}/hipl-%{version}.tar.gz
Packager: hipl-dev@freelists.org
Vendor: InfraHIP
Copyright: GPL
Group: System Environment/Kernel
Requires: openssl
ExclusiveOS: linux

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
./configure --prefix=%{_prefix} --bindir=%{_bindir} --mandir=%{_mandir} && make
make -C doc all

%install
rm -rf ${RPM_BUILD_ROOT}
install -d ${RPM_BUILD_ROOT}%{_bindir}
install -d ${RPM_BUILD_ROOT}%{_sbindir}
install -d ${RPM_BUILD_ROOT}%{_libdir}
install -d ${RPM_BUILD_ROOT}%{_docdir}
make install
install -m 644 doc/HOWTO.txt ${RPM_BUILD_ROOT}%{_docdir}

%clean
rm -rf ${RPM_BUILD_ROOT}

# Note: we are not distributing everything from test directory, just essentials
%files
%defattr (-, root, root)
%{_sbindir}/hipd
%{_sbindir}/hipconf
%{_bindir}/hipsetup
%{_bindir}/conntest-client
%{_bindir}/conntest-client-gai
%{_bindir}/conntest-client-native
%{_bindir}/conntest-client-native-user-key
%{_bindir}/conntest-server
%{_bindir}/conntest-server-native
%{_libdir}/libinet6.a
%{_libdir}/libinet6.so
%{_libdir}/libinet6.so.0.0.0
%{_libdir}/libinet6.la
%{_libdir}/libinet6.so.0
%dir /etc/hip
%doc doc/HOWTO.txt doc/howto-html

%changelog
* Mon May 6 2006 Miika Komu <miika@iki.fi>
- Minor changes. Works, finally!
* Fri May 5 2006 Miika Komu <miika@iki.fi>
- Renamed to hipl.spec (original was from Mika) and modularized
* Tue Feb 14 2006 Miika Komu <miika@iki.fi>
- added changelog
