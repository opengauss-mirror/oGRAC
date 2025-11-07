# 容器开发编译部署手册
## 大纲
 - [环境准备](#section1)
 - [编译部署](#section2)
 - [卸载清理](#section3)
 - [调试](#section5)
 - [定位分析](#section6)

<a id="section1"></a>
## 环境准备

### 目录组织

例：
新建编译目录ogdb_compile，后续操作均在此目录下展开
```
drwxr-xr-x 16 root root      4096 Sep 25 18:10 oGRAC // oGRAC 源码目录
drwxr-xr-x  4 root root      4096 Sep 25 18:11 ograc_data // ograc 数据文件目录
```

### 下载最新docker镜像

```shell
# x86版本
docker pull ykfnxx/cantian_dev:0.1.0
# arm版本
docker pull ykfnxx/cantian_dev:0.1.1
# x决定是arm/x86版本
docker tag ykfnxx/cantian_dev:0.1.[x] cantian_dev:latest
```

### 准备代码

```shell
git clone https://gitcode.com/opengauss/oGRAC.git
```

<a id="start_docker"></a>
### 启动开发编译自验容器
需进入oGRAC代码目录  
单节点
```shell
sh docker/container.sh dev
sh docker/container.sh enterdev
```
双节点
```shell
# 目前只支持双节点，node_id为0, 1（代表0号节点或1号节点）
sh docker/container.sh startnode [node_id]
sh docker/container.sh enternode [node_id]
```

```shell
# 单节点：
sh docker/container.sh dev
# 双节点0：
sh docker/container.sh startnode [0]
sh docker/container.sh enternode [0]
# 双节点1：
sh docker/container.sh startnode [1]
sh docker/container.sh enternode [1]
```

<a id="section2"></a>
## 编译部署

### oGRAC编译

以下命令在容器内使用。若为双节点，则只需在其中一个节点执行一次。为方便描述，后续双节点仅需在一个节点的操作默认在node0进行
```shell
cd /home/regress/oGRACKernel/build
export local_build=true
# 若此前编译过第三方依赖，可以修改Makefile.sh文件中func_all函数，将func_prepare_dependency注释掉，避免重复编译三方依赖。
# debug
sh Makefile.sh package
# release
sh Makefile.sh package-release
```

### oGRAC部署
#### 残留文件清理
```shell
kill -9 $(pidof ogracd)
kill -9 $(pidof cms)
rm -rf /home/regress/ograc_data/* /home/regress/install /home/regress/data /home/ogracdba/install/* /data/data/* /home/ogracdba/data
sed -i '/ogracdba/d' /home/ogracdba/.bashrc
```

#### 单节点oGRAC部署
```shell
cd /home/regress/oGRACKernel/oGRAC-DATABASE-CENTOS-64bit
mkdir -p /home/ogracdba/logs
# -Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数
python3 install.py -U ogracdba:ogracdba -R /home/ogracdba/install -D /home/ogracdba/data -l /home/ogracdba/logs/install.log -Z _LOG_LEVEL=255 -g withoutroot -d -M ogracd -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```
#### 双节点oGRAC部署
节点0，在容器内执行以下命令
```shell
# -Z SESSIONS=1000方便调试，需运行MTR时需要去掉此参数
cd /home/regress/oGRACKernel/oGRAC-DATABASE-CENTOS-64bit
mkdir -p /home/ogracdba/logs
python3 install.py -U ogracdba:ogracdba -R /home/ogracdba/install -D /home/ogracdba/data -l /home/ogracdba/logs/install.log -M ogracd_in_cluster -Z _LOG_LEVEL=255 -N 0 -W 192.168.0.1 -g withoutroot -d -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```
节点1，在容器内执行以下命令
```shell
#节点1，在容器内执行以下命令
cd /home/regress/oGRACKernel/oGRAC-DATABASE-CENTOS-64bit
mkdir -p /home/ogracdba/logs
python3 install.py -U ogracdba:ogracdba -R /home/ogracdba/install -D /home/ogracdba/data -l /home/ogracdba/logs/install.log -M ogracd_in_cluster -Z _LOG_LEVEL=255 -N 1 -W 192.168.0.1 -g withoutroot -d -c -Z _SYS_PASSWORD=Huawei@123 -Z SESSIONS=1000
```

#### 验证oGRAC状态是否正常

```shell
su - ogracdba
cms stat
ogsql / as sysdba -q -c 'SELECT NAME, STATUS, OPEN_STATUS FROM DV_DATABASE'
```

### gdb调试
gdb调试oGRAC前请先设置心跳
``` Bash  
su ogracdba
cms res -edit db -attr HB_TIMEOUT=1000000000
cms res -edit db -attr CHECK_TIMEOUT=1000000000
```

如果有进程coredump问题，需要解析内存转储文件分析堆栈
<a id="section6"></a>
## 定位分析
### 配置core_pattern
配置core_pattern后，即可在对应core_pattern目录生成coredump文件
```Bash  
echo "/home/core/core-%e-%p-%t" > /proc/sys/kernel/core_pattern
echo 2 > /proc/sys/fs/suid_dumpable
ulimit -c unlimited
```

### 解析coredump

```Bash
解ogracd
gdb /home/regress/oGRACKernel/output/bin/ogracd /home/core/core文件名
```

### 分析日志

```
# oGRAC日志目录
/home/ogracdba/data/log/run/ogracd.rlog
# 打开ogracd debug日志
su - ogracdba
ogsql / as sysdba
show parameter LOG;
alter system set _LOG_LEVEL_MODE=FATAL即可生效
# ograc debug日志目录
/home/ogracdba/data/log/debug/ogracd.dlog
```

### UT测试
1. 在对应模块添加测试代码
``` Bash
# 对应模块目录
pkg/test/unit_test/ut/...
# 如增加测试文件则需要修改对应模块下的CMakeLists.txt
set(DEMO_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/cms/cms_test_main.cpp
                ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/cms/cms_disk_lock_test.cpp
                ...)
# (注意)项目中包含.c和.cpp的混合编译，注意编写 extern "C" 的合理使用。
```
2. 执行测试脚本[Dev_unit_test.sh](https://gitcode.com/opengauss/oGRAC/blob/master/CI/script/Dev_unit_test.sh)
``` Bash
sh CI/script/Dev_unit_test.sh  
# 如果已经编译过ograc，可以注释掉make_ograc_pkg。
```
3. 查看测试结果
```Bash
oGRACKernel/output/bin  # UT二进制bin文件所在目录
oGRACKernel/gtest_run.log  # 运行日志
oGRACKernel/lcov_output    # 代码覆盖率测试结果(需要安装lcov)
oGRACKernel/gtest_result   # 每个UT用例的xml结果
```