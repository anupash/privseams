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
BuildRoot: %{_tmppath}/%{name}-%{version}-root

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
./configure --bindir=%{buildroot}/%{_bindir} --sbindir=%{buildroot}/%{_sbindir} --datadir=%{buildroot}/%{_datadir} --sysconfdir=%{buildroot}/%{_sysconfdir} --libdir=%{buildroot}/%{_libdir} --includedir=%{buildroot}/%{_includedir} --infodir=%{buildroot}/%{_infodir} --mandir=%{buildroot}/%{_bindir} && make
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
install -d %{buildroot}/%{_bindir}
install -d %{buildroot}/%{_sbindir}
install -d %{buildroot}/%{_libdir}
install -d %{buildroot}/%{_docdir}
install -d %{buildroot}/etc/rc.d/init.d
make install
install -m 644 doc/HOWTO.txt %{buildroot}/%{_docdir}
install -m 700 test/packaging/rh-init.d-hipd %{buildroot}/etc/rc.d/init.d/hipd

%pre
if [ -x /etc/rc.d/init.d/hipd ]; then
	/etc/rc.d/init.d/hipd stop
fi

%post
/sbin/chkconfig --add hipd

%preun
/etc/rc.d/init.d/hipd stop

%postun
/sbin/chkconfig --del hipd


%clean
rm -rf %{buildroot}

# Note: we are not distributing everything from test directory, just essentials
%files
%defattr (-, root, root)
%{_sbindir}/hipconf
%{_sbindir}/hipd
%{_bindir}/hipsetup
%{_bindir}/conntest-client
%{_bindir}/conntest-client-gai
%{_bindir}/conntest-client-native
%{_bindir}/conntest-client-native-user-key
%{_bindir}/conntest-server
%{_bindir}/conntest-server-native
%{_libdir}/*
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
