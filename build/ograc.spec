# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

Name:ograc
Version:1.0.0
Release:00
License:#None
Group:Applications/Productivity
Source:ograc.tar.gz
Summary:ograc service
BuildRoot:%{_tmppath}/%{name}-%{version}-%{release}-root
Vendor:Huawei Technologies Co., Ltd
%define user_path /opt/ograc/image
%define __os_install_post %{nil}


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

%post
chmod +x -R %{user_path}

%files
%defattr(-,root,root)
%{user_path}