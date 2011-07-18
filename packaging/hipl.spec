Name: hipl
Summary: HIP IPsec key management and mobility daemon
# Note: Version and Release are generated and prefixed automatically to this file
#       by packaging/create-package.sh
URL: http://infrahip.hiit.fi/
Source: http://infrahip.hiit.fi/hipl/release/%{version}/noarch/hipl-%{version}.tar.gz
Packager: miika@iki.fi
Vendor: InfraHIP
License: GPLv2 and MIT
Group: System Environment/Daemons
BuildRequires: gcc autoconf automake libtool xmlto openssl-devel iptables-devel rpm-build python >= 2.4.3
ExclusiveOS: linux
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Prefix: /usr

%description

The Host Identity Protocol (HIP) provides cryptographic authentication
between hosts and secure communications using IPsec. HIP protocol
extensions also support mobility, multihoming and NAT traversal.

HIP for Linux (HIPL) is an implementation of HIP that consists of
the key and mobility management daemon plus other related tools.

%prep
%setup -q

# Note: in subsequent releases me may want to use --disable-debugging
%build
autoreconf --install
%configure --prefix=/usr --sysconfdir=/etc
make %{?_smp_mflags}

%define _unpackaged_files_terminate_build 0
%define _missing_doc_files_terminate_build 0
%define python_sitelib %(%{__python} -c 'from distutils import sysconfig; print sysconfig.get_python_lib()')


# Note: we are not distributing everything from test directory, just essentials

# create subpackage
# list of files with the name of subpackage

%package all
Summary: Full HIPL software bundle
Group: System Environment/Daemons
Requires: hipl-firewall hipl-daemon hipl-doc hipl-dnsproxy
%description all
Full HIPL software bundle. This virtual package is suitable e.g. for clients.

%package daemon
Requires: openssl perl-Net-IP perl-Net-DNS
Obsoletes: minimal tools
Summary: HIP for Linux IPsec key management and mobility daemon
Group: System Environment/Daemons
%description daemon
HIP for Linux IPsec key management and mobility daemon.

%package firewall
Requires: openssl iptables
Summary: HIPL multi-purpose firewall daemon
Group: System Environment/Daemons
%description firewall
HIPL multi-purpose firewall daemon. Public-key/HIT-based access control,
Local Scope Identifier support, userspace BEET-mode IPsec (for kernels
below < 2.6.27) and system-based opportunistic mode for HIP.

%package doc
Summary: Documentation for HIP for Linux
Group: Documentation
%description doc
Documentation for HIP for Linux.

%package dnsproxy
Requires: python
Summary: Name look-up proxy for HIP for Linux
Group: System Environment/Daemons
%description dnsproxy
Name look-up proxy for HIP for Linux. Intercepts DNS look-ups and returns
HIT or LSIs when corresponding entries are found in DNS or hosts files.

%install
rm -rf %{buildroot}

make install-strip DESTDIR=%{buildroot}
# Workaround for CentOS 5.6
install -d %{buildroot}%{_datadir}/doc/hipl
install -d %{buildroot}/etc/rc.d/init.d
install -pm 755 packaging/fedora-init.d/hipfw %{buildroot}/etc/rc.d/init.d/hipfw
install -pm 755 packaging/fedora-init.d/hipd %{buildroot}/etc/rc.d/init.d/hipd
install -pm 755 packaging/fedora-init.d/dnsproxy %{buildroot}/etc/rc.d/init.d/hipdnsproxy


# Remove files that are not being packaged on purpose from buildroot, to shut
# up some RPM warnings about unpackaged files. The doc files do get packaged,
# but still cause warnings for some reason, this works around that fact.
rm -r %{buildroot}%{_datadir}/doc/hipl
rm    %{buildroot}%{_bindir}/auth_performance
rm    %{buildroot}%{_bindir}/certteststub
rm    %{buildroot}%{_bindir}/hc_performance
rm    %{buildroot}%{_libdir}/libhipcore.a
rm    %{buildroot}%{_libdir}/libhipcore.la

%post daemon
if [ "$1" = "2" ]; then
        # upgrade
        /sbin/service hipd restart
else
        # first install
        /sbin/chkconfig --add hipd
        /sbin/chkconfig --level 2 hipd on
        /sbin/service hipd start
fi

%preun daemon
if [ "$1" = "0" ]; then
        # remove daemon completely
        /sbin/service hipd stop
        /sbin/chkconfig --del hipd
fi

%post dnsproxy
if [ "$1" = "2" ]; then
        # upgrade
        /sbin/service hipdnsproxy restart
else
        # first install
        /sbin/chkconfig --add hipdnsproxy
        /sbin/chkconfig --level 2 hipdnsproxy on
        /sbin/service hipdnsproxy start
fi

%preun dnsproxy
if [ "$1" = "0" ]; then
        # remove daemon completely
        /sbin/service hipdnsproxy stop
        /sbin/chkconfig --del hipdnsproxy
fi

%post firewall
if [ "$1" = "2" ]; then
        # upgrade
        /sbin/service hipfw restart
else
        # first install
        /sbin/chkconfig --add hipfw
        /sbin/chkconfig --level 2 hipfw on
        /sbin/service hipfw start
fi

%preun firewall
if [ "$1" = "0" ]; then
        # remove daemon completely
        /sbin/service hipfw stop
        /sbin/chkconfig --del hipfw
fi

%clean
rm -rf %{buildroot}

%files daemon
%defattr(755,root,root,-)
%{_sbindir}/hipd
%{_sbindir}/hipconf
%{_sbindir}/pisacert
%{_sbindir}/nsupdate.pl
%config /etc/rc.d/init.d/hipd

%files dnsproxy
%defattr(755,root,root,755)
%{_sbindir}/hipdnsproxy
%{_sbindir}/hipdnskeyparse
%{python_sitelib}/hipdnsproxy
%{python_sitelib}/hipdnskeyparse
%{python_sitelib}/DNS
%config /etc/rc.d/init.d/hipdnsproxy

%files firewall
%defattr(755,root,root,-)
%{_sbindir}/hipfw
%config /etc/rc.d/init.d/hipfw

%files doc
%defattr(644,root,root,-)
%doc doc/HOWTO.txt doc/HOWTO.html
%doc doc/base-exchange-relay.png doc/base-exchange-rvs.png
%doc doc/docshot-agent-main-window.png doc/docshot-agent-tray-icon.png

%files all


%changelog
* Wed Dec 31 2008 Miika Komu <miika@iki.fi>
- Packaging improvements and lots of testing
* Wed Aug 20 2008 Miika Komu <miika@iki.fi>
- Dnsproxy separated into a separate package. Python packaging improvements.
* Mon Jul 21 2008 Miika Komu <miika@iki.fi>
- Rpmbuild fixes for Fedora 8 build
* Thu Jul 17 2008 Johnny Hughes <johnny@centos.org>
- added two perl searches and installed one directory in the spec file
- added libtool, libcap-devel and xmlto to BuildRequires
* Thu May 29 2008 Juha Jylhakoski <juha.jylhakoski@hiit.fi>
- Split hipl.spec was split to different packages
* Tue May 9 2006 Miika Komu <miika@iki.fi>
- init.d script, buildroot
* Mon May 6 2006 Miika Komu <miika@iki.fi>
- Minor changes. Works, finally!
* Fri May 5 2006 Miika Komu <miika@iki.fi>
- Renamed to hipl.spec (original was from Mika) and modularized
* Tue Feb 14 2006 Miika Komu <miika@iki.fi>
- added changelog
