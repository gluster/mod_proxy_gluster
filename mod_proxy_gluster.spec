%{!?_httpd_apxs:       %{expand: %%global _httpd_apxs       %%{_sbindir}/apxs}}
%{!?_httpd_confdir:    %{expand: %%global _httpd_confdir    %%{_sysconfdir}/httpd/conf.d}}
# /etc/httpd/conf.d with httpd < 2.4 and defined as /etc/httpd/conf.modules.d with httpd >= 2.4
%{!?_httpd_modconfdir: %{expand: %%global _httpd_modconfdir %%{_sysconfdir}/httpd/conf.d}}
%{!?_httpd_mmn: %{expand: %%global _httpd_mmn %%(cat %{_includedir}/httpd/.mmn 2>/dev/null || echo 0-0)}}

Name:		mod_proxy_gluster
Version:	0.8.1
Release:	0.1%{?dist}
Summary:	Gluster support module for mod_proxy
Group:		System Environment/Daemons
License:	ASL 2.0
URL:		https://forge.gluster.org/mod_proxy_gluster
#Source: 	http://forge.gluster.org/mod_proxy_gluster/mod_proxy_gluster/%{name}-%{version}.tar.gz
Source: 	%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:	httpd-devel, apr-devel
BuildRequires:	glusterfs-api-devel >= 3.4, glusterfs-devel
BuildRequires:	pkgconfig
Requires:	httpd-mmn = %{_httpd_mmn}
Requires(post):	httpd

%description
mod_proxy and related modules implement a proxy/gateway for Apache HTTP Server,
supporting a number of popular protocols as well as several different load
balancing algorithms.

This module adds support for accessing Gluster Volumes without the need to
mount them with glusterfs-fuse or NFS. The purpose is to serve static contents.
Files are returned without passing through any interpreters. mod_proxy_gluster
is not intended to be used for storing web-applications (written in languages
like PHP).


%prep
%setup -q


%build
#CFLAGS="$RPM_OPT_FLAGS $(pkg-config glusterfs-api --cflags --libs)"
CFLAGS="$(pkg-config glusterfs-api --cflags-only-I --libs-only-l)"

%{_httpd_apxs} -c ${CFLAGS} mod_proxy_gluster.c


%install
# The install target of the Makefile isn't used because that uses apxs
# which tries to enable the module in the build host httpd instead of in
# the build root.
rm -rf $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf
mkdir -p $RPM_BUILD_ROOT%{_httpd_confdir}
mkdir -p $RPM_BUILD_ROOT%{_libdir}/httpd/modules

%if "%{_httpd_modconfdir}" != "%{_httpd_confdir}"
# httpd >= 2.4.x
mkdir -p $RPM_BUILD_ROOT%{_httpd_modconfdir}
sed -n /^LoadModule/p mod_proxy_gluster.conf.example > 01-proxy-gluster.conf
sed -i /^LoadModule/d mod_proxy_gluster.conf.example
install -m 644 01-proxy-gluster.conf $RPM_BUILD_ROOT%{_httpd_modconfdir}
%endif

install -m 755 .libs/mod_proxy_gluster.so $RPM_BUILD_ROOT%{_libdir}/httpd/modules/


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc README LICENSE mod_proxy_gluster.conf.example
%if "%{_httpd_modconfdir}" != "%{_httpd_confdir}"
%config(noreplace) %{_httpd_modconfdir}/01-proxy-gluster.conf
%endif
%{_libdir}/httpd/modules/mod_proxy_gluster.so


%changelog
* Tue Mar 25 2014 Niels de Vos <ndevos@redhat.com> 0.8.1-0.1
- Update to version 0.8.1
- Require glusterfs-api-devel >= 3.4, for glfs_readdir_r()
- Add glusterfs-devel as BuildRequires, see RHBZ#1017094

* Mon Mar 24 2014 Niels de Vos <ndevos@redhat.com> 0.8-0.1
- Initial packaging, with hints from mod_nss.spec
