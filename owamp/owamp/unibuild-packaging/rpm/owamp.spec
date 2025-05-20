#
# Adapted from the spec in the sources
#

%define perfsonar_auto_version 5.2.0
%define perfsonar_auto_relnum 0.3.b1

Name: owamp
Summary: owamp - one-way delay tester
Version: %{perfsonar_auto_version}
Release: %{perfsonar_auto_relnum}%{?dist}
License: ASL 2.0 
Group: *Development/Libraries*
URL: http://e2epi.internet2.edu/owamp/

Source: %{name}-%{version}.tar.gz
Patch0: owamp-00-root-test.patch

Packager: The perfSONAR Development Team <perfsonar-developer@internet2.edu>
BuildRequires: libtool, I2util, libcap-devel, openssl-devel, systemd, selinux-policy-devel
Requires: owamp-client, owamp-server, I2util

%description
OWAMP is a client/server package that allows one to measure the latency between
hosts. Unlike ping, which can only measure the bidirectional delay, OWAMP
enables you to measure the unidirectional delay between two hosts.


%define build_devel 0

%global debug_package %{nil}


%files

%package -n twamp
Summary: twamp - two-way delay tester
Requires: twamp-client, twamp-server, I2util

%description -n twamp
TWAMP is a client/server package that allows one to measure the latency between
hosts.

%files -n twamp

%package -n owamp-client
Summary: owamp client
Group: Applications/Network
%description -n owamp-client
owamp command line utilities for performing owamp measurements with an owamp
server.

%package -n twamp-client
Summary: twamp client
Group: Applications/Network
%description -n twamp-client
twamp command line utilities for performing twamp measurements with an twamp
server.

%package -n owamp-server
Summary: owamp server
Group: Applications/Network
Requires: shadow-utils, coreutils
%{?systemd_requires: %systemd_requires}
%if 0%{?el7}
# SELinux support
Requires: policycoreutils-python, libselinux-utils
Requires(post): selinux-policy-targeted, policycoreutils-python
Requires(postun): policycoreutils-python
%else
#Requirements for > el7
Requires: policycoreutils-python-utils, python3-policycoreutils, libselinux-utils
Requires(post): policycoreutils-python-utils, selinux-policy-targeted, python3-policycoreutils
Requires(postun): policycoreutils-python-utils, python3-policycoreutils
%endif
%description -n owamp-server
owamp server

%package -n twamp-server
Summary: twamp server
Group: Applications/Network
Requires: shadow-utils, coreutils
%{?systemd_requires: %systemd_requires}
%if 0%{?el7}
# SELinux support
Requires: policycoreutils-python, libselinux-utils
Requires(post): selinux-policy-targeted, policycoreutils-python
Requires(postun): policycoreutils-python
%else
#Requirements for > el7
Requires: policycoreutils-python-utils, python3-policycoreutils, libselinux-utils
Requires(post): policycoreutils-python-utils, selinux-policy-targeted, python3-policycoreutils
Requires(postun): policycoreutils-python-utils, python3-policycoreutils
%endif
%description -n twamp-server
twamp server

%if %{build_devel}
%package devel
Group: Development/Libraries
Summary: owamp library headers.
%description devel
This package includes header files, and static link libraries for building
applications that use the owamp library.
%endif

# Thrulay and I2Util get installed, but really, shouldn't be instaled.
%define _unpackaged_files_terminate_build      0

%pre -n owamp-client
/usr/sbin/groupadd -r owamp 2> /dev/null || :
/usr/sbin/useradd -g owamp -r -s /bin/nologin -d /tmp owamp 2> /dev/null || :

%pre -n twamp-client
/usr/sbin/groupadd -r twamp 2> /dev/null || :
/usr/sbin/useradd -g twamp -r -s /bin/nologin -d /tmp twamp 2> /dev/null || :

%pre -n owamp-server
/usr/sbin/groupadd -r owamp 2> /dev/null || :
/usr/sbin/useradd -g owamp -r -s /bin/nologin -d /tmp owamp 2> /dev/null || :

%pre -n twamp-server
/usr/sbin/groupadd -r twamp 2> /dev/null || :
/usr/sbin/useradd -g twamp -r -s /bin/nologin -d /tmp twamp 2> /dev/null || :

%prep
%setup -q -n "%{name}-%{version}"
%patch0 -p1


%build
./bootstrap
%configure --with-I2util=no
make
make -f /usr/share/selinux/devel/Makefile -C selinux owamp-server.pp
make -f /usr/share/selinux/devel/Makefile -C selinux twamp-server.pp

%install
%makeinstall
%{__install} -D -p -m 0644 conf/owampd.service %{buildroot}%{_unitdir}/owamp-server.service
%{__install} -D -p -m 0755 conf/owampd.init %{buildroot}%{_sysconfdir}/rc.d/init.d/owamp-server
%{__install} -D -p -m 0644 conf/owampd.limits %{buildroot}%{_sysconfdir}/owamp-server/owamp-server.limits
%{__install} -D -p -m 0644 conf/owampd.rpm.conf %{buildroot}%{_sysconfdir}/owamp-server/owamp-server.conf
%{__install} -D -p -m 0644 conf/owampd.limits %{buildroot}%{_sysconfdir}/owamp-server/owamp-server.limits.default
%{__install} -D -p -m 0644 conf/owampd.rpm.conf %{buildroot}%{_sysconfdir}/owamp-server/owampd.conf.default
%{__install} -D -p -m 0755 conf/owampd-cleanup %{buildroot}%{_sysconfdir}/cron.daily/owamp-server

%{__install} -D -p -m 0644 conf/twampd.service %{buildroot}%{_unitdir}/twamp-server.service
%{__install} -D -p -m 0755 conf/twampd.init %{buildroot}%{_sysconfdir}/rc.d/init.d/twamp-server
%{__install} -D -p -m 0644 conf/twampd.rpm.conf %{buildroot}%{_sysconfdir}/twamp-server/twamp-server.conf
%{__install} -D -p -m 0644 conf/twampd.rpm.conf %{buildroot}%{_sysconfdir}/twamp-server/twamp-server.conf.default
%{__install} -D -p -m 0644 conf/twampd.limits %{buildroot}%{_sysconfdir}/twamp-server/twamp-server.limits
%{__install} -D -p -m 0644 conf/twampd.limits %{buildroot}%{_sysconfdir}/twamp-server/twamp-server.limits.default

mkdir -p %{buildroot}/usr/share/selinux/packages/
mv selinux/*.pp %{buildroot}/usr/share/selinux/packages/
rm -rf %{buildroot}/usr/lib/perfsonar/selinux

%check
make check

%clean
rm -rf $RPM_BUILD_ROOT 

%post -n owamp-client
setcap "cap_net_raw+p" %{_bindir}/owping
setcap "cap_net_raw+p" %{_bindir}/powstream

%post -n owamp-server

#create data dir (must be prior to selinux)
mkdir -p /var/lib/owamp/hierarchy
chown -R owamp:owamp /var/lib/owamp

semodule -n -i %{_datadir}/selinux/packages/owamp-server.pp
semanage port -a -t owamp_port_t -p tcp 861 2>/dev/null
semanage port -a -t owamp_test_port_t -p udp 8760-9960 2>/dev/null
if /usr/sbin/selinuxenabled; then
    /usr/sbin/load_policy
    restorecon -iR /etc/owamp-server /usr/bin/owampd \
                   /usr/lib/systemd/system/owamp-server.service \
                   /var/lib/owamp /var/run/owamp-server.*
fi

%systemd_post owamp-server.service
if [ "$1" = "1" ]; then
    systemctl enable owamp-server.service
    systemctl start owamp-server.service
fi

%preun -n owamp-server
%systemd_preun owamp-server.service

%postun -n owamp-server
%systemd_postun_with_restart owamp-server.service

if [ $1 -eq 0 ]; then
    semanage port -d -p tcp 861
    semanage port -d -p udp 8760-9960
    semodule -n -r owamp-server
    if /usr/sbin/selinuxenabled; then
       /usr/sbin/load_policy
       restorecon -iR /etc/owamp-server /usr/bin/owampd \
                      /usr/lib/systemd/system/owamp-server.service \
                      /var/lib/owamp /var/run/owamp-server.*
    fi
fi

if [ "$1" = "0" ]; then
	/usr/sbin/userdel owamp || :
fi

%post -n twamp-client
setcap "cap_net_raw+p" %{_bindir}/twping

%post -n twamp-server

#create data dir (must be prior to selinux)
mkdir -p /var/lib/twamp
chown -R twamp:twamp /var/lib/twamp

semodule -n -i %{_datadir}/selinux/packages/twamp-server.pp
semanage port -a -t twamp_port_t -p tcp 862 2>/dev/null
semanage port -a -t twamp_test_port_t -p udp 18760-19960 2>/dev/null
if /usr/sbin/selinuxenabled; then
    /usr/sbin/load_policy
    restorecon -iR /etc/twamp-server /usr/bin/twampd \
                   /usr/lib/systemd/system/twamp-server.service \
                   /var/lib/twamp /var/run/twamp-server.*
fi

%systemd_post twamp-server.service
if [ "$1" = "1" ]; then
    systemctl enable twamp-server.service
    systemctl start twamp-server.service
fi

%preun -n twamp-server
%systemd_preun twamp-server.service

%postun -n twamp-server
%systemd_postun_with_restart twamp-server.service

if [ $1 -eq 0 ]; then
    semanage port -d -p tcp 862
    semanage port -d -p udp 18760-19960
    semodule -n -r twamp-server
    if /usr/sbin/selinuxenabled; then
       /usr/sbin/load_policy
       restorecon -iR /etc/twamp-server /usr/bin/twampd \
                      /usr/lib/systemd/system/twamp-server.service \
                      /var/lib/twamp /var/run/twamp-server.*
    fi
fi

if [ "$1" = "0" ]; then
	/usr/sbin/userdel twamp || :
fi

%files -n owamp-client
%defattr(0644,root,root,0755)
%license LICENSE
%doc README
%attr(0755,root,root) %{_bindir}/owfetch
%attr(0755,root,root) %{_bindir}/owping
%attr(0755,root,root) %{_bindir}/owstats
%attr(0755,root,root) %{_bindir}/owup
%attr(0755,root,root) %{_bindir}/powstream
%{_mandir}/man1/owfetch.1.gz
%{_mandir}/man1/owping.1.gz
%{_mandir}/man1/owstats.1.gz
%{_mandir}/man1/owup.1.gz
%{_mandir}/man1/powstream.1.gz

%files -n twamp-client
%defattr(0644,root,root,0755)
%license LICENSE
%attr(0755,root,root) %{_bindir}/twping
%{_mandir}/man1/twping.1.gz

%files -n owamp-server
%license LICENSE
%defattr(0644,root,root,0755)
%attr(0755,root,root) %{_bindir}/owampd
%{_mandir}/man5/owamp*
%{_mandir}/man8/owamp*
%config(noreplace) %{_sysconfdir}/owamp-server/*
%{_unitdir}/owamp-server.service
%attr(0644,root,root) %{_datadir}/selinux/packages/owamp-server.pp
%attr(0755,root,root) %{_sysconfdir}/cron.daily/owamp-server

%files -n twamp-server
%defattr(0644,root,root,0755)
%license LICENSE
%attr(0755,root,root) %{_bindir}/twampd
%{_mandir}/man5/twamp*
%{_mandir}/man8/twamp*
%config(noreplace) %{_sysconfdir}/twamp-server/*
%{_unitdir}/twamp-server.service
%attr(0644,root,root) %{_datadir}/selinux/packages/twamp-server.pp

%if %{build_devel}
%files devel
%defattr(0644,root,root,0755)
%license LICENSE
%{_libdir}/libbwlib.a
%{_includedir}/owamp/*
%endif

%changelog
* Thu Mar 26 2009 aaron@internet2.edu 1.0-4
- Make upgrading work more seamlessly

* Thu Mar 26 2009 aaron@internet2.edu 1.0-3
- Make sure that /var/lib/owamp is created on install

* Mon Feb 02 2009 aaron@internet2.edu 1.0-2
- Fix the example owampd.limits location

* Fri Aug 22 2008 aaron@internet2.edu 1.0-1
- Initial RPM
