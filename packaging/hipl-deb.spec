Name: hipl
Summary: HIP IPsec key management and mobility daemon.
# Note: Version and Release are generated and prefixed automatically to this file
#       by packaging/create-package.sh
# Note: To check that this file is in correct format, type
# ./debbuild --showpkgs hipl-deb.spec
URL: http://infrahip.hiit.fi/
Source: http://infrahip.hiit.fi/hipl/release/sources/%{version}/hipl-%{version}.tar.gz
Packager: miika@iki.fi
Vendor: InfraHIP
License: GPLv2 and MIT/Expat
Group: System Environment/Kernel
BuildRequires: gcc, automake, autoconf, libtool, xmlto, libssl-dev, iptables-dev, dpkg-dev, pax
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
%setup

# Note: in subsequent releases me may want to use --disable-debugging
%build
autoreconf --install
%configure --prefix=/usr --sysconfdir=/etc
make -j 32

# Note:
# This debbuild script is fragile and does not tolerate comments well.
# Keep all comments and notes here.
#
# Note:
#
# Currently we are not going to install all includes and test software.
# As a consequence, we need to tell rpmbuild that we don't want to package
# everything and need the following two lines. In fact, the build fails
# without them). However, you might want to uncomment the lines temporarily
# before building the final release just to check that you have not discarded
# any essential files.
#
#%define _unpackaged_files_terminate_build 0
#%define _missing_doc_files_terminate_build 0
#%define python_sitelib __python -c 'from distutils import sysconfig; print sysconfig.get_python_lib()')


# Note: we are not distributing everything from test directory, just essentials

# create subpackage
# list of files with the name of subpackage
#
# Note: earlier the contents of "all" was just "."
# It doesn't work anymore with Rene's changes to the update version of
# debbuild. Currently they include some files to get the binaries compiled.
# Fix this workaround.
#
# Note: the post rules used to be like this (does not work anymore)
# - update-rc.d hipfw start 20 S . stop 80 0 6 .
# - invoke-rc.d --quiet hipdnsproxy start

%package all
Summary: Full HIPL software bundle. This virtual package is suitable e.g. for client machines.
Group: System Environment/Kernel
Requires: hipl-firewall, hipl-daemon, hipl-doc, hipl-dnsproxy
%description all

%package daemon
Requires: openssl, iptables, libnet-ip-perl, libnet-dns-perl
Obsoletes: minimal, tools
Summary: HIP for Linux IPsec key management and mobility daemon
Group: System Environment/Kernel
%description daemon

%package firewall
Requires: openssl, iptables
Summary: HIPL multi-purpose firewall daemon. Public-key/HIT-based access control, Local Scope Identifier support, userspace BEET-mode IPsec (for kernels below < 2.6.27) and system-based opportunistic mode for HIP.
Group: System Environment/Kernel
%description firewall

%package doc
Summary: documentation for HIP for Linux
Group: System Environment/Kernel
%description doc

%package dnsproxy
Requires: python
Summary: Name look-up proxy for HIP for Linux. Intercepts DNS look-ups and returns HIT or LSIs when corresponding entries are found in DNS or hosts files
Group: System Environment/Kernel
%description dnsproxy

%install
rm -rf %{buildroot}

make install-strip DESTDIR=%{buildroot}
install -d %{buildroot}/etc/init.d
install -m 755 packaging/debian-init.d/hipfw %{buildroot}/etc/init.d/hipfw
install -m 755 packaging/debian-init.d/hipd %{buildroot}/etc/init.d/hipd
install -m 755 packaging/debian-init.d/dnsproxy %{buildroot}/etc/init.d/hipdnsproxy

%post daemon
update-rc.d hipd defaults 21
invoke-rc.d --quiet hipd status >/dev/null && invoke-rc.d --force --quiet hipd stop
invoke-rc.d hipd start

%post firewall
update-rc.d hipfw defaults 20
invoke-rc.d --quiet hipfw status >/dev/null && invoke-rc.d --force --quiet hipfw stop
invoke-rc.d hipfw start

%post dnsproxy
update-rc.d hipdnsproxy defaults 22
invoke-rc.d --quiet hipdnsproxy status >/dev/null && invoke-rc.d --force --quiet hipdnsproxy stop
invoke-rc.d hipdnsproxy start

%preun daemon
invoke-rc.d --quiet hipd status >/dev/null && invoke-rc.d --force --quiet hipd stop
update-rc.d -f hipd remove

%preun firewall
invoke-rc.d --quiet hipfw status >/dev/null && invoke-rc.d --force --quiet hipfw stop
update-rc.d -f hipfw remove

%preun dnsproxy
invoke-rc.d --quiet hipdnsproxy status >/dev/null && invoke-rc.d --force --quiet hipdnsproxy stop
update-rc.d -f hipdnsproxy remove

%clean
rm -rf %{buildroot}

%files daemon
/usr/sbin/hipd
/usr/sbin/hipconf
/usr/sbin/pisacert
/usr/sbin/nsupdate.pl
%defattr(755,root,root)
%config /etc/init.d/hipd

%files dnsproxy
/usr/sbin/hipdnsproxy
/usr/sbin/hipdnskeyparse
/usr/lib/python2.6/dist-packages
%defattr(755,root,root)
%config /etc/init.d/hipdnsproxy

%files firewall
/usr/sbin/hipfw
%config /etc/init.d/hipfw

%files doc
%doc doc/HOWTO.txt doc/HOWTO.html
%doc doc/base-exchange-relay.png doc/base-exchange-rvs.png
%doc doc/docshot-agent-main-window.png doc/docshot-agent-tray-icon.png

%files all


%changelog
* Fri Nov 20 2009 Miika Komu <miika@iki.fi>
- Loads of new stuff, including enhanced mobility
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
