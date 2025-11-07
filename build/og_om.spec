Name:og_om
Version:1.0.0
Release:00
License:#None
Group:Applications/Productivity
Source:og_om.tar.gz
Summary:og_om service
BuildRoot:%{_tmppath}/%{name}-%{version}-%{release}-root
Vendor:Huawei Technologies Co., Ltd
%define user_path /opt/ograc/og_om
%define __os_install_post %{nil}


%description
This package include:
ServiceTool og_om module

%prep
%setup -c -n %{name}-%{version}

%install
install -d $RPM_BUILD_ROOT%{user_path}/
cp -a * $RPM_BUILD_ROOT%{user_path}/

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/%{name}-%{version}

%files
%defattr(0400,ogmgruser,ogmgruser)
%dir %attr (0770,ogmgruser,ogmgruser) %{user_path}
%dir %attr (0770,ogmgruser,ogmgruser) %{user_path}/service
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ograc_exporter
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ograc_exporter/scripts
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ograc_exporter/exporter
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ograc_exporter/config
%attr (0600,ogmgruser,ogmgruser) %{user_path}/service/ogcli/commands.json
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ogcli
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ogcli/params_factory
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ogmgr
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ogmgr/scripts
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ogmgr/checker
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ogmgr/logs_collection
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ogmgr/checker
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ogmgr/log_tool
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ogmgr/tasks
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ogmgr/common
%dir %attr (0700,ogmgruser,ogmgruser) %{user_path}/service/ogmgr/tasks/inspection
%attr (0600,ogmgruser,ogmgruser) %{user_path}/service/ogmgr/format_note.json
%attr (0600,ogmgruser,ogmgruser) %{user_path}/service/ogmgr/logs_collection/log_packing_progress.json
%{user_path}