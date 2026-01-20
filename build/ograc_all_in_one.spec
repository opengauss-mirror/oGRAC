Name:ograc_all_in_one
Version:1.0.0
Release:00
License:#None
Group:Applications/Productivity
Source:ograc_all_in_one.tar.gz
Summary:ograc_all_in_one service
BuildRoot:%{_tmppath}/%{name}-%{version}-%{release}-root
Vendor:Huawei Technologies Co., Ltd
%define user_path /opt/ograc
%define __os_install_post %{nil}
%define config_file /opt/config_params_lun.json
%define gccdisk /dev/gcc-disk
%define dssdisk1 /dev/dss-disk1
%define dssdisk2 /dev/dss-disk2
%define dssdisk3 /dev/dss-disk3

%description
This package include:
ServiceTool ograc module

%prep
%setup -c -n %{name}-%{version}

%install
install -d $RPM_BUILD_ROOT%{user_path}/
cp -a * $RPM_BUILD_ROOT%{user_path}/

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/%{name}-%{version}

%pre
#!/bin/bash
set -e
if [ ! -f "%{config_file}" ]; then
    echo "ERROR: Config file /opt/config_params_lun.json not exsits, installation aborted!" >&2
    exit 1
fi

if [[ ! -b "%{gccdisk}" ]] || [[ ! -b "%{dssdisk1}" ]] || [[ ! -b "%{dssdisk2}" ]] || [[ ! -b "%{dssdisk3}" ]]; then
    echo "ERROR: The required device(LUN) /dev/gcc-disk, /dev/dss-disk1, /dev/dss-disk2, /dev/dss-disk3 not exsit, installation aborted!" >&2
    exit 1
fi

exit 0

%post
#!/bin/bash
set -e
CONFIG_SOURCE="%{config_file}"
chmod +x -R %{user_path}
\cp "${CONFIG_SOURCE}" %{user_path}/action
cd %{user_path}/action
sh appctl.sh install config_params_lun.json

%preun
#!/bin/bash
set -e
cd %{user_path}/action
sh appctl.sh stop
sh appctl.sh uninstall override

%postun
#!/bin/bash
rm -rf %{user_path} 2>/dev/null

%files
%defattr(-,root,root)
%{user_path}