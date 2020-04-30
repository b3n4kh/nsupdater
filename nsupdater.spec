%define version 1
%define release 2
%define name dhcpdns
%define debug_package %{nil}
%define _build_id_links none

Name:           %{name}
Version:        %{version}
Release:        %{release}
Summary:        Create DNS Entries for DHCP Events
License:        Beerware
URL:            https://github.com/b3n4kh/dhcpdns
Source0:        %{name}-%{version}.%{release}.tar.gz

ExclusiveArch:  %{go_arches}
Requires: systemd nginx
BuildRequires: systemd
Requires(pre): shadow-utils

%description
Create DNS Entries for DHCP Events

%prep
%setup -n %{name}

%post

%build
mkdir -p ./_build/src/github.com/b3n4kh/
ln -s $(pwd) ./_build/src/github.com/b3n4kh/%{name}

export GOPATH=$(pwd)/_build:%{gopath}
go build -o bin/%{name} .

%install
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/%{name}
install -p -m 755 bin/%{name} %{buildroot}%{_bindir}
install -p -m 644 config.json %{buildroot}%{_sysconfdir}/%{name}

%files
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
%config(noreplace) %{_sysconfdir}/%{name}/config.json

