## 什么是oGRAC

oGRAC是openGauss社区经过多年的技术沉淀和探索，秉承着做最具创新力的技术根社区的精神，以做高性能、高安全、高可用、高智能的满足客户诉求的数据库为初心，在架构、事务、优化器和存储引擎上从零自主创新，打造的业界首个开源的多主关系型数据库。

RAC是“Real Application Clusters”的缩写，是集中式数据库的一种典型架构，一般采用了存算分离的架构，计算任务在各个节点上执行，存储节点通过共享的集中式存储来实现。RAC架构下集群具备强一致的应用透明多写能力，用户可以像使用单机数据库使用集群；同时提供了集群的高可用能力，只要有任一存活节点，集群仍可提供正常的服务。

oGRAC使用存算分离架构，实现计算、内存、存储三层池化。通过全局分布式缓存技术、分布式MVCC、分布式锁、多主集群高可用等关键技术，支持集群多读多写能力。

## oGRAC架构

oGRAC主要由五个主要部分组成：

-   CMS（Cluster Manager Service）: 负责集群管理。
-   SQL引擎：oGRAC的SQL引擎通过基于规则的查询重写和基于代价的物理优化生成最优的执行计划。
-   存储引擎：oGRAC存储引擎是基于共享存储的支持多主的存储引擎，各个节点在架构上对等，从任何一个节点都可以对数据库做DDL/DML/DCL等操作。任何一个节点做的修改，其他节点都可以看到满足其事务一致性的数据，所有计算节点共享和读写存储上同一份用户数据。
-   DSS（Distribute Storage Service）：分布式存储服务，给数据库提供统一的底层存储接口，向下管理不同类型的存储形态，支持集中式和分布式存储。
-   工具：包括备份恢复工具、运维管理工具等。

更详细的oGRAC架构介绍，请参考[架构描述](https://docs.opengauss.org/zh/docs/latest/ograc/about_ograc/product_architecture/architecture_description.html)。

## 工程说明

-   编程语言：C
-   编译工程：cmake或make，建议使用cmake
-   目录说明：

|目录名称   | 说明  |
|---|---|
|build | 编译构建oGRAC数据库的脚本 |
|og_om | 安装部署脚本。|
|docker | 构建、启动oGRAC容器镜像的相关脚本。|
|library | 编译oGRAC需要的一些三方库头文件。|
|pkg | oGRAC源代码目录，子目录代表不同的功能模块。|

## 单节点编译部署指南

请注意，单节点模式仅用于个人开发验证，不适用于生产环境。单节点不包含 DMS/DSS 等分布式组件能力，不支持多写，也无法平滑扩展为多节点集群。

> * 单节点模式仅支持单实例运行
> * 不包含 `DMS`、`DSS` 等分布式组件能力
> * 不支持多写场景，也无法在当前环境基础上平滑扩展为多节点集群
> * 仅建议用于开发、调试和问题定位

1. 环境准备

- 当前安装目录限制为 `/home/` 下，需保证有足够空间（至少 20580 MB）
- 操作系统仅支持英文语言环境，否则会影响数据库启动
- 数据库可独占内存需满足 16 GB

2. 系统初始化

    执行以下命令完成相关配置：

    ```shell
    setenforce 0
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    systemctl stop firewalld
    systemctl disable firewalld
    ```

    > * `setenforce 0`：临时关闭 SELinux 强制策略
    > * 修改 `/etc/selinux/config` 可保证系统重启后仍保持关闭状态
    > * 防火墙关闭后，请确保当前环境为可信内网或本地环境

3. 创建目录与用户

    建议使用独立的系统用户进行 oGRAC 安装和运行：

    ```shell
    mkdir -p [compile_path]
    useradd [user_name]
    passwd [user_password]
    # 建议进行权限设置，否则会出现 install 阶段权限不足的报错
    chmod -R 777 [compile_path]
    ```

    > * `[compile_path]` 为源码下载、编译及安装的统一工作目录。
    > * `[user_name]`：建议专用于 oGRAC 的系统运行用户

4. 安装系统依赖

    ```shell
    yum install -y wget git python3 python3-devel iputils iproute \
    unixODBC-devel unixODBC lz4 lz4-devel patch xz flex --skip-broken
    ```

    > * `python3 / python3-devel`：用于执行安装脚本和管理工具
    > * `iputils / iproute`：用于网络检测与 IP 配置
    > * `lz4`：用于数据压缩与解压，要求版本 >= 1.8.3
    > * `--skip-broken`：在依赖存在冲突时跳过异常包，避免中断安装

5. 源码获取与编译

    （1）拉取源码：

    ```shell
    cd [compile_path]
    git clone https://gitcode.com/opengauss/oGRAC.git
    ```

    （2）执行 prepare 阶段准备环境依赖：

    ```shell
    cd oGRAC/build
    sh local_install.sh prepare
    ```

    （3）如需编译 debug 版本，建议关闭保护虚拟内存选项：

    ```shell
    cd oGRAC/build
    sed -i 's/DUSE_PROTECT_VM=ON/DUSE_PROTECT_VM=OFF/g' Makefile.sh
    ```

    （4）编译：

    ```shell
    sh local_install.sh compile -b [release | debug]
    ```

    > * `[release | debug]`：指定编译模式，`release` 为默认值，`debug` 为调试模式

6. 安装流程

    （1）执行安装脚本

    * 在 root 用户下，进入 `oGRAC/build` 目录
    * 使用安装脚本进行部署，并指定安装用户或者兼容性

    ```bash
    sh local_install.sh install -u [user_name]

    # sh local_install.sh install -u [user_name] -c A  # 新建兼容性为A的数据库
    ```

    该脚本将自动完成以下工作：

    * 校验运行环境和用户权限
    * 创建安装用户及 home 目录（如不存在）
    * 停止并清理历史残留进程与数据
    * 创建数据目录和日志目录

    当执行完成后，可以登录到 `-u` 指定的用户下，使用 `ogsql / as sysdba` 命令连接数据库，进行使用。

    当需要重启时，可以使用如下命令启动数据库：

    ```shell
    /home/[user_name]/install/bin/ogracd -D /home/[user_name]/data &
    ```

    （2）卸载与清理

    如需重新部署或清理环境，可执行卸载脚本：

    ```shell
    sh local_install.sh clean -u [user_name]
    ```

    该操作会停止服务，并删除数据目录、安装目录及相关环境变量。

    > * 上述配置仅建议在调试环境中使用
    > * 调试完成后可恢复默认配置，避免影响系统行为

更多其他详情请参考[官方单节点安装指南](https://docs.opengauss.org/zh/docs/latest/ograc/installation_guide/single_node_guide/local_installation_on_a_single_node.html)。

---

## 容器化单节点安装指南	 

请注意，单节点仅用于个人开发验证，不建议用于生产环境。另外，容器化部署暂时仅支持单实例运行，不支持多写，也无法平滑扩展为多节点集群。

1. 下载 docker 镜像	 
 
    ```shell	 
    wget https://repo.openeuler.org/openEuler-22.03-LTS/docker_img/aarch64/openEuler-docker.aarch64.tar.xz	 
    	 
    docker load < ./openEuler-docker.aarch64.tar.xz	 
    ``` 

2. 启动 docker 

    ```shell 
    docker run --name mirror_name -itd -v /home/uer_name/docker/data:/home --privileged=true --network=host --shm-size=128g IMAGE_ID 
    ``` 
     
    - -v 是 docker 的挂载，将宿主机的 `/home/uer_name/docker/data` 目录挂载到容器内的 `/home` 目录下 
    - --shm-size 是 docker 的共享内存大小，这里设置为 128g，建议不要小于128g 
    - IMAGE_ID 是 docker 镜像的 ID，可以通过 `docker images` 查看 

3. Docker 镜像内配置 


    安装依赖： 
    ```shell 
    yum install -y git unzip vim 
    ``` 

4. 查看镜像文件 

   在 root 用户下输入： 
     
    ```shell 
    docker images 
    ``` 

    正常情况下会回显如下信息： 
    
    ```shell 
    REPOSITORY    TAG        IMAGE ID        CREATED                 SIZE 
    mirror_name   latest    xxxx            About a minute ago      3.71GB 
    ``` 

5. 创建并进入新的容器 

    ```shell 
    docker run -it --name=mirror_namenode mirror_name /bin/bash 
    
    --name=mirror_namenode表示规定容器的名字是什么； 
    
    mirror_name表示以哪个镜像实例化 
    ``` 

6. 在容器内编译 oGRAC 

    下载源码 

    ```shell 
    git clone https://gitcode.com/opengauss/oGRAC.git 
    ``` 

    修改 Makefile.sh （如果编译debug版本，建议执行这步，否则可能会出现编译失败）
    
    ```shell 
    sed -i 's+USE_PROTECT_VM=ON+USE_PROTECT_VM=OFF+' Makefile.sh 
    ``` 

7. 编译安装 oGRAC 

    在 build 目录下执行下面的命令进行编译安装，示例为编译的 debug 版本，不指定 -b 默认是编译 release 版本；-u 指定安装用户名 
    
    ```shell 
    sh local_install.sh prepare 
    
    sh local_install.sh compile -b debug 
    
    sh local_install.sh install -u user_name 
    ```
更多其他详情请参考[官方容器化单节点安装指南](https://docs.opengauss.org/zh/docs/latest/ograc/installation_guide/single_node_guide/containerized_single_node_installation.html)

---

## 双节点编译部署指南

双节点部署适用于功能验证、测试及多主能力体验。整体分为**本地编译出包**和**两节点集群安装**两个阶段。

> 注意：两节点部署需要共享存储环境（至少 4 块裸 LUN），且仅建议在测试或非生产环境中按本文档关闭 SELinux 与防火墙。

### 编译出包

1. 编译环境准备

    （1）系统初始化（root 用户执行）：

    ```shell
    setenforce 0
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    systemctl stop firewalld
    systemctl disable firewalld
    ```

    （2）创建编译目录与用户：

    ```shell
    mkdir -p [compile_path]
    chmod 755 -R [compile_path]
    useradd [user_name]
    passwd [user_name]
    chown -R [user_name]:[user_name] [compile_path]
    ```

    （3）安装系统依赖：

    ```shell
    yum install -y libaio-devel openssl openssl-devel ndctl-devel unixODBC-devel unixODBC \
    ncurses ncurses-devel libtirpc-devel expect ant bison iputils \
    iproute wget make gcc gcc-c++ gdb gdb-gdbserver python3 python3-devel \
    git net-tools cmake automake byacc libtool lz4 lz4-devel patch xz flex --skip-broken
    ```

    > 依赖要求：`cmake >= 3.12`，`lz4 >= 1.8.3`。若为 openEuler 24.03 LTS，需使用 GCC 10.3 手动编译 cmake，详见[官方双节点编译出包指南](https://docs.opengauss.org/zh/docs/latest/ograc/installation_guide/two_nodes_guide/compiling_the_version_two_node.html)。

2. 编译流程

    （1）下载源码与三方库：

    ```shell
    su - [user_name]
    cd [compile_path]

    git clone https://gitcode.com/opengauss/oGRAC.git
    cd oGRAC

    wget --no-check-certificate \
    https://opengauss.obs.cn-south-1.myhuaweicloud.com/6.0.0/binarylibs/gcc10.3/openGauss-third_party_binarylibs_openEuler_2203_arm.tar.gz

    tar -zxf openGauss-third_party_binarylibs_openEuler_2203_arm.tar.gz
    ```

    > 请确保第三方库解压目录与 oGRAC 源码目录同级。

    （2）如需编译 debug 版本，建议关闭保护虚拟内存：

    ```shell
    cd [compile_path]/oGRAC/build
    sed -i 's/DUSE_PROTECT_VM=ON/DUSE_PROTECT_VM=OFF/g' Makefile.sh
    ```

    （3）执行编译：

    ```shell
    cd [compile_path]/oGRAC/build
    sh build_ograc.sh [release|debug] --with-dss
    ```

    > 若三方库不在默认路径，可通过 `--third-party-path <path>` 指定（路径需在 oGRAC 目录内）。

    （4）编译产物位于：

    ```shell
    [compile_path]/oGRAC/package/
    ```

### 两节点部署

1. 安装前须知

    - 主机数量：2 台 ARM 架构物理机或虚拟机
    - 单节点推荐配置：内存 ≥ 16 GB，CPU ≥ 8 核，磁盘可用空间 ≥ 100 GB
    - 共享盘：至少 4 块裸 LUN 盘（未分区），两节点均可访问
    - 支持系统：openEuler 20.03/22.03/24.03 LTS（aarch64）

2. 安装准备

    在两节点上分别使用 root 用户执行：

    （1）系统初始化：

    ```shell
    setenforce 0
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    systemctl stop firewalld
    systemctl disable firewalld
    ```

    （2）安装依赖：

    ```shell
    yum install -y wget git ntpdate chrony python3 python3-devel iputils iproute patchelf lz4 --skip-broken
    ```

    > 要求 `lz4 >= 1.8.3`。openEuler 20.03 无 patchelf 源包，需手动编译安装，详见[官方双节点编译出包指南](https://docs.opengauss.org/zh/docs/latest/ograc/installation_guide/two_nodes_guide/compiling_the_version_two_node.html)。

    （3）创建安装目录并下载/解压安装包：

    ```shell
    mkdir -p /data/ograc
    cd /data/ograc
    tar -zxvf openGauss-oGRAC-openEuler[os_version]-aarch64-RELEASE.tgz
    chmod -R 777 ograc_connector
    chown -R root:root ograc_connector
    ```

3. 共享存储准备

    建议 4 块 LUN 规划如下：

    | 用途 | 建议大小 | 软链接 |
    |------|----------|--------|
    | CM 仲裁盘 | 5 GB | `/dev/gcc-disk` |
    | 数据盘 | 2 TB | `/dev/dss-disk1` |
    | Redo 盘 | 4 TB | `/dev/dss-disk2` |
    | 归档盘 | 2 TB | `/dev/dss-disk3` |

    创建软链接并授权：

    ```shell
    ln -s /dev/disk/by-id/[scsi-disk1] /dev/dss-disk1
    ln -s /dev/disk/by-id/[scsi-disk2] /dev/dss-disk2
    ln -s /dev/disk/by-id/[scsi-disk3] /dev/dss-disk3
    ln -s /dev/disk/by-id/[scsi-disk4] /dev/gcc-disk
    chmod 777 /dev/sdX  # 替换为对应盘符
    ```

4. 时间同步

    若两节点时间不一致，需进行时间同步。可外网环境：

    ```shell
    ntpdate -u [ntp_server]
    ```

    无外网环境建议以节点 0 为时间服务器，节点 1 向节点 0 同步,详见[官方双节点部署指南](https://docs.opengauss.org/zh/docs/latest/ograc/installation_guide/two_nodes_guide/ograc_two_node_installation.html)。

5. 配置安装参数

    编辑配置文件：

    ```shell
    cd /data/ograc/ograc_connector/action
    vim config_params_lun.json
    ```

    节点 0 示例：

    ```json
    {
        "deploy_mode": "dss",
        "node_id": "0",
        "cms_ip": "xxx.xxx.xxx.xxx;xxx.xxx.xxx.xxx",
        "db_type": "1",
        "mes_ssl_switch": false,
        "MAX_ARCH_FILES_SIZE": "300G",
        "redo_num": "6",
        "redo_size": "5G",
        "auto_tune": "1",
        "dss_vg_list": {
            "vg1": "/dev/dss-disk1",
            "vg2": "/dev/dss-disk2",
            "vg3": "/dev/dss-disk3"
        },
        "gcc_home": "/dev/gcc-disk",
        "cms_port": "14587",
        "dss_port": "1811",
        "ograc_port": "1611",
        "interconnect_port": "1601,1602",
        "_SHM_KEY": 17,
        "module_config": {
            "ograc_home": "/data/ograc_install/ograc",
            "data_root": "/data/ograc_install/dbdata",
            "user": "ograc"
        }
    }
    ```

    节点 1 仅需将 `node_id` 改为 `"1"`，其余保持一致。

    > 配置要点：
    > - `node_id` 必须为 0 和 1
    > - 小规格机器建议 `auto_tune = 1`
    > - `redo_num × redo_size × 2` 应小于 Redo 盘容量
    > - 多数据库环境建议 `_SHM_KEY` 改为唯一值

    （可选）修改数据库兼容性：

    ```shell
    vim ograc/install_config.json
    ```

    ```json
    {
    "DBCOMPATIBILITY": "A"
    }
    ```

6. 安装与启动

    建议先完成节点 0 安装，再安装节点 1。

    （1）预安装：

    ```shell
    sh appctl.sh pre_install config_params_lun.json
    ```

    （2）安装：

    ```shell
    sh appctl.sh install config_params_lun.json
    ```

    安装过程中需设置 sys 用户密码，两节点密码必须相同。

    （3）启动：

    ```shell
    sh appctl.sh start
    ```

    建议先启动节点 0，再启动节点 1。节点 0 首次启动会创建 Redo 和数据文件，耗时较长。

7. 集群状态检查

    在任意节点执行：

    ```shell
    su -s /bin/bash ograc
    cms stat -res db
    ```

    当两节点 `STAT` 列均为 `ONLINE` 时，集群状态正常。

    数据库功能验证：

    ```shell
    su -s /bin/bash ograc
    ogsql / as sysdba -q
    ```

    在节点 0 创建表并插入数据，在节点 1 查询，如能查到即表示功能正常。

8. 重新安装

    如需重新部署，先停止再卸载清理：

    ```shell
    sh appctl.sh stop
    sh appctl.sh uninstall override
    ```

    然后可更换包版本或修改配置后重新安装。

更多详情请参考[官方两节点编译指南](https://docs.opengauss.org/zh/docs/latest/ograc/installation_guide/two_nodes_guide/compiling_the_version_two_node.html)和[官方两节点安装指南](https://docs.opengauss.org/zh/docs/latest/ograc/installation_guide/two_nodes_guide/ograc_two_node_installation.html)。

## 单元测试

oGRAC 使用 SQL 回归测试验证基础功能，测试用例位于 `pkg/test/og_regress/`，如下操作步骤以单节点进行测试为例。

### 1. 环境准备

运行简易测试前，请确保：

- 操作系统为 openEuler 20.03 / 22.03 / 24.03
- 当前用户为 **root**（脚本需要创建用户、安装 `lcov`、执行 `su` 切换等）
- 内存 ≥ 16 GB，磁盘可用空间 ≥ 50 GB
- 系统语言环境为英文（否则可能影响数据库启动）

### 2. 清理环境（必须）

`do_all_test.sh need_compile` 会触发完整编译，要求环境处于**未编译、未安装的干净状态**。如果之前编译过或安装过数据库，旧编译产物和数据库实例会导致第二次编译安装失败。

依次执行以下命令彻底清理：

```shell
# 进入代码目录
cd /home/regress/ogracKernel

# 停止并卸载已安装的数据库
sh build/local_install.sh clean -u ogracdba

# 清理测试编译产物和数据目录
rm -rf /home/regress/og_regress/*
rm -rf /home/regress/ograc_data/*

# 删除旧用户（如果存在）
id ogracdba >/dev/null 2>&1 && userdel -r ogracdba
id ogracdba >/dev/null 2>&1 || groupdel ogracdba 2>/dev/null || true
```

> **注意**：`rm -rf /home/regress/*` 会删除该目录下所有内容，请确认目录内无重要数据后再执行。如果当前环境本身就是干净的（首次运行），可跳过此步骤。

### 3. 关闭保护虚拟内存（debug 编译建议执行）

编译 debug 版本时，建议先关闭保护虚拟内存选项：

```shell
cd /home/regress/ogracKernel
sed -i 's+USE_PROTECT_VM=ON+USE_PROTECT_VM=OFF+' build/Makefile.sh
```

### 4. 执行测试

```shell
bash pkg/test/og_regress/do_all_test.sh need_compile
```

参数说明：

| 参数 | 含义 |
|---|---|
| `need_compile` | 触发完整编译。如果已经编译过，可省略此参数直接运行 |
| （不传参） | 跳过编译，使用 `output/bin` 下已有的二进制 |

### 5. 查看结果

脚本执行完成后，最终会在控制台输出：

```
Test Result: Success   # 全部通过
Test Result: ERROR     # 存在失败用例
```

详细结果和日志位置：

| 文件/目录 | 说明 |
|---|---|
| `regress_output/test_result.txt` | 最终测试结果 |
| `regress_output/LLT_log_part_all.txt` | 完整运行日志 |
| `regress_output/LLT_result_part_all.txt` | 截取的回归结果汇总 |
| `pkg/test/og_regress/results/**/*.diff` | 失败用例的 diff 文件 |
| `/home/regress/og_regress/logs/regress_log` | 回归运行日志 |
| `/home/regress/og_regress/logs/compile_log` | 编译日志 |

## 文档

更多安装指南、教程和API请参考[用户文档](https://docs.opengauss.org/zh/docs/latest/ograc/about_ograc/product_description/ograc_overview.html)。

## 下载

下载体验oGRAC请参考[下载](https://download-opengauss.osinfra.cn/archive_test/oGRAC/)

## 社区

### 治理

查看openGauss是如何实现开放[治理](https://gitcode.com/opengauss/community/blob/master/governance.md)。

### 交流

- 线上交流：https://opengauss.org/zh/community/onlineCommunication/
- 社区论坛：https://discuss.opengauss.org/

## 贡献

欢迎大家来参与贡献。详情请参阅我们的[社区贡献](https://opengauss.org/zh/contribution/)。

## 许可证

[MulanPSL-2.0](http://license.coscl.org.cn/MulanPSL2)
