
Name: hipl
Summary: HIP IPsec key management and mobility daemon.
# Note: Version and Release are read automatically from topdir release.version
URL: http://infrahip.hiit.fi/
Source: http://infrahip.hiit.fi/hipl/release/sources/%{version}/hipl-%{version}.tar.gz
Packager: miika@iki.fi
Vendor: InfraHIP
License: GPLv2
Group: System Environment/Kernel
BuildRequires: gcc gcc-c++ openssl-devel libxml2-devel iptables-devel xmlto libtool libcap-devel autoconf automake xmlto rpm-build
ExclusiveOS: linux
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Prefix: /usr

%description

Host Identity Protocol (HIP) provides cryptographic authentication to
between hosts and secure communications using IPsec. HIP protocol
extensions support also mobility and multihoming, and traversal of NATs.

HIP for Linux (HIPL) is an implementation of a HIP implementation that
consists of the key and mobility management daemon. It includes also
other related tools.
%prep
%setup

# Note: in subsequent releases me may want to use --disable-debugging
%build
autoreconf --install
%configure --prefix=/usr
make -j 4 all

# Currently we are not going to install all includes and test software.
# As a consequence, we need to tell rpmbuild that we don't want to package
# everything and need the following two lines. In fact, the build fails
# without them). However, you might want to uncomment the lines temporarily
# before building the final release just to check that you have not discarded
# any essential files.
#
#%define _unpackaged_files_terminate_build 0
#%define _missing_doc_files_terminate_build 0
%define python_sitelib %(%{__python} -c 'from distutils import sysconfig; print sysconfig.get_python_lib()')


# Note: we are not distributing everything from test directory, just essentials

# create subpackage
# list of files with the name of subpackage

# XX TODO: copy descriptions from hipl-deb.spec and make sure rpm still builds

%package all
Summary: Full HIPL software bundle. This virtual package is suitable e.g. for client machines.
Group: System Environment/Kernel
Requires: hipl-lib hipl-firewall hipl-daemon hipl-tools hipl-doc hipl-dnsproxy
%description all

%package minimal
Summary: Minimal HIPL software bundle for servers. This virtual package is suitable for e.g. servers.
Group: System Environment/Kernel
Requires: hipl-lib hipl-daemon hipl-tools
%description minimal

%package lib
Summary: HIP for Linux libraries
Group: System Environment/Kernel
Requires: openssl libxml2 iptables libcap
%description lib

%package daemon
Requires: hipl-lib perl-Net-IP perl-Net-DNS perl-Socket6 perl-IO-Socket-INET6
Summary: HIP for Linux IPsec key management and mobility daemon
Group: System Environment/Kernel
%description daemon

%package tools
Requires: hipl-lib hipl-daemon
Summary: Command line tools to control hipd from command line
Group: System Environment/Kernel
%description tools

%package firewall
Requires: hipl-lib
Summary: HIPL multi-purpose firewall daemon. Public-key/HIT-based access control, Local Scope Identifier support, userspace BEET-mode IPsec (for kernels below < 2.6.27) and system-based opportunistic mode for HIP.
Group: System Environment/Kernel
%description firewall

%package doc
Summary: documentation for HIP for Linux
Group: System Environment/Kernel
%description doc

%package dnsproxy
Requires: python hipl-lib
Summary: Name look-up proxy for HIP for Linux. Intercepts DNS look-ups and returns HIT or LSIs when corresponding entries are found in DNS, DHT or hosts files
Group: System Environment/Kernel
%description dnsproxy

%install
rm -rf %{buildroot}

#added by CentOS
install -d %{buildroot}%{prefix}/share/pixmaps
#end CentOS add

# XX FIXME: add more python stuff from tools directory

install -d %{buildroot}%{prefix}/bin
install -d %{buildroot}%{prefix}/sbin
install -d %{buildroot}%{prefix}/lib
install -d %{buildroot}/etc/rc.d/init.d
install -d %{buildroot}/doc
make DESTDIR=%{buildroot} install
install -m 755 packaging/fedora-init.d/hipfw %{buildroot}/etc/rc.d/init.d/hipfw
install -m 755 packaging/fedora-init.d/hipd %{buildroot}/etc/rc.d/init.d/hipd
install -m 755 packaging/fedora-init.d/dnsproxy %{buildroot}/etc/rc.d/init.d/hipdnsproxy
install -m 644 doc/HOWTO.txt %{buildroot}/doc
install -d %{buildroot}%{python_sitelib}/DNS
install -t %{buildroot}%{python_sitelib}/DNS tools/hipdnsproxy/DNS/*py*
install -d %{buildroot}%{python_sitelib}
install -t %{buildroot}%{python_sitelib} tools/hipdnsproxy/pyip6.py*
install -t %{buildroot}%{python_sitelib} tools/hipdnsproxy/hosts.py*
install -t %{buildroot}%{python_sitelib} tools/hipdnsproxy/util.py*
install -t %{buildroot}%{python_sitelib} tools/hipdnskeyparse/myasn.py*
# required in CentOS release 5.2
install -m 755 tools/hipdnskeyparse/hipdnskeyparse %{buildroot}%{prefix}/sbin/hipdnskeyparse
install -m 755 tools/hipdnsproxy/hipdnsproxy %{buildroot}%{prefix}/sbin/hipdnsproxy

%post lib
/sbin/ldconfig

%post daemon
if [ "$1" = "2" ]
then
        # upgrade
        /sbin/service hipd restart
else
        # first install
        /sbin/chkconfig --add hipd
        /sbin/chkconfig --level 2 hipd on
        /sbin/service hipd start
fi

%preun daemon
if [ "$1" = "0" ]
then
        # removing package completely
        /sbin/service hipd stop
        /sbin/chkconfig --del hipd
fi

%post dnsproxy
if [ "$1" = "2" ]
then
        # upgrade
        /sbin/service hipdnsproxy restart
else
        # first install
        /sbin/chkconfig --add hipdnsproxy
        /sbin/chkconfig --level 2 hipdnsproxy on
        /sbin/service hipdnsproxy start
fi

%preun dnsproxy
if [ "$1" = "0" ]
then
        # removing package completely
        /sbin/service hipdnsproxy stop
        /sbin/chkconfig --del hipdnsproxy
fi

%post firewall
if [ "$1" = "2" ]
then
        # upgrade
        /sbin/service hipfw restart
else
        # first install
        /sbin/chkconfig --add hipfw
        /sbin/chkconfig --level 2 hipfw on
        /sbin/service hipfw start
fi

%preun firewall
if [ "$1" = "0" ]
then
        # removing package completely
        /sbin/service hipfw stop
        /sbin/chkconfig --del hipfw
fi

%clean
rm -rf %{buildroot}

# XX TODO: 64-bit binaries should go to lib64 not lib
%files lib
%{_libdir}

%files daemon
%{prefix}/sbin/hipd
%config /etc/rc.d/init.d/hipd

%files dnsproxy
%{prefix}/sbin/hipdnsproxy
%{prefix}/sbin/hipdnskeyparse
%{python_sitelib}/hipdnsproxy
%{python_sitelib}/hipdnskeyparse
%{python_sitelib}/DNS
%defattr(755,root,root)
%config /etc/rc.d/init.d/hipdnsproxy

%files tools
%{prefix}/sbin/hipconf
%{prefix}/sbin/nsupdate.pl
%defattr(755,root,root)

%files firewall
%{prefix}/sbin/hipfw
%config /etc/rc.d/init.d/hipfw

%files doc
%doc doc/HOWTO.txt doc/howto-html

%files all

%files minimal


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