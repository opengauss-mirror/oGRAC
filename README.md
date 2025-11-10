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

更详细的oGRAC架构介绍，请参考[架构描述](https://gitcode.com/opengauss/oGRAC_DOC/blob/master/%E4%BA%A7%E5%93%81%E6%8F%8F%E8%BF%B0/%E4%BA%A7%E5%93%81%E6%9E%B6%E6%9E%84/%E6%9E%B6%E6%9E%84%E6%8F%8F%E8%BF%B0.md)。

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

## 编译指南

1. 系统初始化

    关闭 SELinux 和防火墙：

    ```shell
    setenforce 0
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    systemctl stop firewalld
    systemctl disable firewalld
    ```

2. 创建目录和用户

    ```shell
    mkdir -p compile_path
    chmod 755 -R compile_path
    useradd user_name
    passwd user_password
    chown -R user_name:user_name compile_path
    ```

3. 安装必要依赖

    ```shell
    yum install -y libaio-devel openssl openssl-devel ndctl-devel \
    ncurses ncurses-devel libtirpc-devel expect ant bison iputils \
    iproute wget make gcc gcc-c++ gdb gdb-gdbserver python3 python3-devel \
    git net-tools cmake automake byacc libtool --skip-broken
    ```

4. 获取源码

    ```shell
    chmod 755 -R compile_path
    cd compile_path
    git clone https://gitcode.com/opengauss/oGRAC.git
    ```

5. 配置修改

    如需关闭保护虚拟内存选项(如果编译安装的是debug版本建议关闭保护虚拟内存选项)：
    
    ```shell
    cd oGRAC/build
    sed -i 's/DUSE_PROTECT_VM=ON/DUSE_PROTECT_VM=OFF/g' Makefile.sh
    ```

6. 编译

    ```shell
    cd build
    sh local_install.sh prepare
    sh local_install.sh compile -b debug
    ```
    
    - `-b, --build_type=<type>`：指定编译类型（release/debug，默认release）

7. 生成目录

    输出包位于：`oGRAC/oGRAC-DATABASE-*-64bit`

## 容器化安装指南

1.下载 docker 镜像

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
    REPOSITORY    TAG        TMAGE ID        CREATED                 SIZE
    mirror_name   lastest    xxxx            About a minute ago      3.71GB
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
 
    修改 Makefile.sh
    
    ```shell
    sed -i 's+USE_PROTECT_VM=ON+USE_PROTECT_VM=OFF+' Makefile.sh
    ```

7. 编译安装 oGRAC

    在 build 目录下执行下面的命令进行编译安装，示例为编译的 debug 版本，不指定 -b 默认是编   译 release 版本；-u 指定安装用户名
    
    ```shell
    sh local_install.sh prepare
    
    sh local_install.sh compile -b debug
    
    sh local_install.sh install -u user_name
    ```

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
