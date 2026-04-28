## What is oGRAC

oGRAC is the industry's first open-source multi-master relational database, developed by the openGauss community through years of technological accumulation and exploration. Guided by the spirit of creating the most innovative technology community, with the mission of delivering high-performance, high-security, high-availability, and high-intelligence databases that meet customer needs, oGRAC achieves zero-to-one innovation in architecture, transactions, optimizer, and storage engine.

RAC stands for "Real Application Clusters", a typical architecture for centralized databases that generally adopts a compute-storage separation design. Compute tasks are executed on various nodes, while storage nodes are implemented through shared centralized storage. Under the RAC architecture, clusters possess strong consistency and application-transparent multi-write capabilities, allowing users to use the cluster like a single-machine database; it also provides cluster high availability, ensuring normal service as long as any node survives.

oGRAC uses a compute-storage separation architecture to achieve three-layer pooling of compute, memory, and storage. Through key technologies such as global distributed caching, distributed MVCC, distributed locking, and multi-master cluster high availability, it supports cluster multi-read and multi-write capabilities.

## oGRAC Architecture

oGRAC mainly consists of five major components:

-   CMS (Cluster Manager Service): Responsible for cluster management.
-   SQL Engine: oGRAC's SQL engine generates optimal execution plans through rule-based query rewriting and cost-based physical optimization.
-   Storage Engine: oGRAC's storage engine is a multi-master storage engine based on shared storage. All nodes are architecturally equivalent, allowing DDL/DML/DCL operations on the database from any node. Modifications made by any node can be seen by other nodes with data that satisfies transactional consistency, and all compute nodes share and read/write the same user data on storage.
-   DSS (Distributed Storage Service): Distributed storage service provides a unified underlying storage interface for the database, managing different storage types downward, supporting both centralized and distributed storage.
-   Tools: Including backup and recovery tools, operation and maintenance management tools, etc.

For a more detailed introduction to oGRAC architecture, please refer to [Architecture Description](https://docs.opengauss.org/zh/docs/latest/ograc/about_ograc/product_architecture/architecture_description.html).

## Project Description

-   Programming Language: C
-   Build Project: cmake or make, recommend using cmake
-   Directory Description:

| Directory Name | Description |
|---|---|
|build | Scripts for compiling and building the oGRAC database |
|og_om | Installation and deployment scripts.|
|docker | Scripts related to building and starting oGRAC container images.|
|library | Third-party library header files needed for compiling oGRAC.|
|pkg | oGRAC source code directory, subdirectories represent different functional modules.|

## Compilation Guide

1. System Initialization

    Disable SELinux and firewall:

    ```shell
    setenforce 0
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    systemctl stop firewalld
    systemctl disable firewalld
    ```

2. Create Directory and User

    ```shell
    mkdir -p compile_path
    chmod 755 -R compile_path
    useradd user_name
    passwd user_password
    chown -R user_name:user_name compile_path
    ```

3. Install Necessary Dependencies

    ```shell
    yum install -y libaio-devel openssl openssl-devel ndctl-devel \
    ncurses ncurses-devel libtirpc-devel expect ant bison iputils \
    iproute wget make gcc gcc-c++ gdb gdb-gdbserver python3 python3-devel \
    git net-tools cmake automake byacc libtool unixODBC-devel --skip-broken
    ```

4. Obtain Source Code

    ```shell
    chmod 755 -R compile_path
    cd compile_path
    git clone https://gitcode.com/opengauss/oGRAC.git
    ```

5. Configuration Modification

    If need to disable protect virtual memory option (if compiling debug version, suggest disabling protect virtual memory option):
    
    ```shell
    cd oGRAC/build
    sed -i 's/DUSE_PROTECT_VM=ON/DUSE_PROTECT_VM=OFF/g' Makefile.sh
    ```

6. Compile

    ```shell
    cd build
    sh local_install.sh prepare
    sh local_install.sh compile -b debug
    ```
    
    - `-b, --build_type=<type>`: Specify compile type (release/debug, default release)

7. Output Directory

    Output package located at: `oGRAC/oGRAC-DATABASE-*-64bit`

## Containerized Installation Guide

1. Download docker image

    ```shell
    wget https://repo.openeuler.org/openEuler-22.03-LTS/docker_img/aarch64/openEuler-docker.aarch64.tar.xz
    
    docker load < ./openEuler-docker.aarch64.tar.xz
    ```

2. Start docker

    ```shell
    docker run --name mirror_name -itd -v /home/uer_name/docker/data:/home --privileged=true --network=host --shm-size=128g IMAGE_ID
    ```
    
    - -v is docker mount, mounting the host's `/home/uer_name/docker/data` directory to the container's `/home` directory
    - --shm-size is docker shared memory size, set to 128g here, suggest not less than 128g
    - IMAGE_ID is the docker image ID, can be viewed with `docker images`

3. Docker image configuration

    Install dependencies:
    ```shell
    yum install -y git unzip vim
    ```

4. View image files

    Input under root user:
    
    ```shell
    docker images
    ```
    
    Normally will echo the following information:
    
    ```shell
    REPOSITORY    TAG        TMAGE ID        CREATED                 SIZE
    mirror_name   lastest    xxxx            About a minute ago      3.71GB
    ```

5. Create and enter new container

    ```shell
    docker run -it --name=mirror_namenode mirror_name /bin/bash
    
    --name=mirror_namenode specifies the container name;
    
    mirror_name specifies which image to instantiate
    ```

6. Compile oGRAC inside container

    Download source code
 
    ```shell
     git clone https://gitcode.com/opengauss/oGRAC.git
    ```
 
    Modify Makefile.sh
    
    ```shell
    sed -i 's+USE_PROTECT_VM=ON+USE_PROTECT_VM=OFF+' Makefile.sh
    ```

7. Compile and install oGRAC

    Execute the following commands in the build directory for compilation and installation. The example is for the debug version; not specifying -b defaults to the release version; -u specifies the installation username
    
    ```shell
    sh local_install.sh prepare
    
    sh local_install.sh compile -b debug
    
    sh local_install.sh install -u user_name
    ```

## Documentation

For more installation guides, tutorials, and API, please refer to [User Documentation](https://docs.opengauss.org/zh/docs/latest/ograc/about_ograc/product_description/ograc_overview.html).

## Download

To download and experience oGRAC, please refer to [Download](https://download-opengauss.osinfra.cn/archive_test/oGRAC/).

## Community

### Governance

View how openGauss implements open [Governance](https://gitcode.com/opengauss/community/blob/master/governance.md).

### Communication

- Online communication: https://opengauss.org/zh/community/onlineCommunication/
- Community forum: https://discuss.opengauss.org/

## Contribution

Everyone is welcome to contribute. For details, please refer to our [Community Contribution](https://opengauss.org/zh/contribution/).

## License

[MulanPSL-2.0](http://license.coscl.org.cn/MulanPSL2)