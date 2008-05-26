Name: hipl
Version: 1.0.4
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
%define python_sitelib %(%{__python} -c 'from distutils import sysconfig; print sysconfig.get_python_lib()')


# Note: we are not distributing everything from test directory, just essentials

# create subpackage
# list of files with the name of subpackage

%package lib
Summary: hip library files
Group: System Environment/Kernel
%description lib

%package daemon
Requires: hipl-lib
Summary: hip daemon files
Group: System Environment/Kernel
%description daemon

%package agent
Requires: hipl-lib, hipl-daemon
Summary: hip agent files
Group: System Environment/Kernel
%description agent

%package tools
Requires: hipl-lib, hipl-daemon
Summary: hip tools files
Group: System Environment/Kernel
%description tools

%package firewall
Summary: hip firewall files
Group: System Environment/Kernel
%description firewall

%package test
Requires: hipl-lib, hipl-daemon
Summary: hip test files
Group: System Environment/Kernel
%description test

%package doc
Summary: hip doc files
Group: System Environment/Kernel
%description doc

%install
rm -rf %{buildroot}
install -d %{buildroot}/%{prefix}/bin
install -d %{buildroot}/%{prefix}/sbin
install -d %{buildroot}/%{prefix}/lib
install -d %{buildroot}/etc/rc.d/init.d
install -d %{buildroot}/doc
make DESTDIR=%{buildroot} install
install -m 700 test/packaging/rh-init.d-hipfw %{buildroot}/etc/rc.d/init.d/hipfw
install -m 700 test/packaging/rh-init.d-hipd %{buildroot}/etc/rc.d/init.d/hipd
install -m 644 doc/HOWTO.txt %{buildroot}/doc
install -d %{buildroot}/%{python_sitelib}/DNS
install -t %{buildroot}/%{python_sitelib}/DNS tools/DNS/*py

%post lib
/sbin/ldconfig 

%post daemon
/sbin/chkconfig --add hipd
/sbin/chkconfig --level 2 hipd on
/sbin/service hipd start

%post firewall
/sbin/chkconfig --add hipfw
/sbin/chkconfig --level 2 hipfw on
/sbin/service hipfw start

%preun daemon
/sbin/service hipd stop
/sbin/chkconfig --del hipd

%preun firewall
/sbin/service hipfw stop
/sbin/chkconfig --del hipfw

%clean
rm -rf %{buildroot}

%files lib
%{_libdir}

%files daemon
%{prefix}/sbin/hipd
%{prefix}/bin/hipsetup
%config /etc/rc.d/init.d/hipd

%files agent
%{prefix}/bin/hipagent

#%{prefix}/bin/DNS/Base.py
#%{prefix}/bin/DNS/Base.pyc
#%{prefix}/bin/DNS/Class.py
#%{prefix}/bin/DNS/Class.pyc
#%{prefix}/bin/DNS/Lib.py
#%{prefix}/bin/DNS/Status.py
#%{prefix}/bin/DNS/Status.pyc
#%{prefix}/bin/DNS/Type.py
#%{prefix}/bin/DNS/Type.pyc
#%{prefix}/bin/DNS/__init__.py
#%{prefix}/bin/DNS/__init__.pyc
#%{prefix}/bin/DNS/lazy.py
#%{prefix}/bin/DNS/lazy.pyc
#%{prefix}/bin/DNS/pyip6.py
#%{prefix}/bin/DNS/win32dns.py

%files tools
%{prefix}/sbin/hipconf
%{prefix}/sbin/myasn.py
%{prefix}/sbin/parse-key-3.py
%{prefix}/sbin/dnsproxy.py
%{prefix}/sbin/hosts.py
%{prefix}/sbin/pyip6.py
%{prefix}/sbin/util.py
%{python_sitelib}/DNS
%defattr(755,root,root)

%files test
%{prefix}/bin/conntest-client-opp
%{prefix}/bin/conntest-client-hip
%{prefix}/bin/conntest-client-native
%{prefix}/bin/conntest-client-native-user-key
%{prefix}/bin/conntest-server
%{prefix}/bin/conntest-server-native

%files firewall
%{prefix}/sbin/hipfw

%files doc
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

