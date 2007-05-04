Name:           memcached
Version:        1.2.2
Release:        1%{?dist}
Summary:        High Performance, Distributed Memory Object Cache

Group:          System Environment/Daemons
License:        BSD
URL:            http://www.danga.com/memcached/
Source0:        http://www.danga.com/memcached/dist/%{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  libevent-devel

Requires:       libevent
Requires:       perl
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig, /sbin/service
Requires(postun): /sbin/service


%description

memcached is a high-performance, distributed memory object caching
system, generic in nature, but intended for use in speeding up dynamic
web applications by alleviating database load.

Available rpmbuild rebuild options :
  --with=threads   - build a multiprocessor optimized memcached server

%prep
%setup -q


%build
%configure \
	%{?_with_threads:--enable-threads}

make %{?_smp_mflags}

%check
# skip this for now, this requires perl and a bunch of other stuff
# and may not work from within rpmbuild
#make test

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

# Perl script monitoring memcached
install -Dp -m0755 $RPM_BUILD_DIR/%{name}-%{version}/scripts/memcached-tool %{buildroot}%{_bindir}/memcached-tool

# Init script
install -Dp -m0755 $RPM_BUILD_DIR/%{name}-%{version}/scripts/memcached.sysv %{buildroot}%{_sysconfdir}/rc.d/init.d/memcached

# Default configs
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig
cat <<EOF >$RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/%{name}
PORT="11211"
USER="nobody"
MAXCONN="1024"
CACHESIZE="64"
OPTIONS=""
EOF

%clean
rm -rf $RPM_BUILD_ROOT


%post
/sbin/chkconfig --add %{name}

%preun
if [ "$1" = 0 ] ; then
    /sbin/service %{name} stop > /dev/null 2>&1
    /sbin/chkconfig --del %{name}
fi
exit 0

%postun
if [ "$1" -ge 1 ]; then
    /sbin/service %{name} condrestart > /dev/null 2>&1
fi
exit 0


%files
%defattr(-,root,root,-)
%doc AUTHORS ChangeLog COPYING NEWS README TODO doc/CONTRIBUTORS doc/*.txt
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%{_bindir}/memcached-tool
%{_bindir}/memcached
%{_bindir}/memcached-debug
%{_mandir}/man1/memcached.1*
%{_sysconfdir}/rc.d/init.d/memcached


%changelog
* Fri May  4 2007 Paul Lindner <lindner@inuus.com> - 1.2.2-1
- Initial spec file created via rpmdev-newspec
