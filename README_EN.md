## What Is oGRAC?

oGRAC is the culmination of years of technical expertise and exploration within the openGauss community. Built with the spirit of creating a highly innovative open-source foundation, oGRAC was designed from the ground up to be a high-performance, high-security, high-availability, and highly intelligent database. It is the industry's first open-source multi-primary relational database, featuring independent innovation across its architecture, transaction processing, optimizer, and storage engine.

RAC stands for Real Application Clusters, a signature architecture for centralized databases that typically employs decoupled storage and compute. In this model, computing tasks are executed across various nodes while storage is managed through a shared, centralized pool. The RAC architecture provides strong consistency, application transparency, and multi-write capabilities for clusters, allowing users to operate the cluster in the same way they would use a standalone database. In addition, the architecture provides high availability for the cluster, ensuring that as long as any single node remains active, the cluster can continue to provide services properly.

Through the use of decoupled storage and compute, oGRAC implements a three-layer pooling of compute, memory, and storage resources. It supports concurrent multi-read and multi-write capabilities through key technologies such as global distributed cache, distributed multi-version concurrency control (MVCC), distributed locking, and multi-primary cluster high availability.

## oGRAC Architecture

The oGRAC architecture is comprised of five core components:

-   Cluster Manager Service (CMS): Responsible for overall cluster management.
-   SQL engine: Generates optimal execution plans using rule-based query rewriting and cost-based physical optimization.
-   Storage engine: A multi-primary storage engine based on shared storage. All nodes are architecturally equivalent. DDL, DML, and DCL operations can be performed from any node. Any modifications made by one node are visible to others while maintaining transaction consistency. All computing nodes share, read, and write the same user data on the storage.
-   Distributed Storage Service (DSS): Acts as a unified storage interface. It manages various storage types and supports both centralized and distributed storage backends.
-   Tools: Include a suite of utilities for backup, recovery, and O&M.

For details about the oGRAC architecture, see [Architecture](https://docs.opengauss.org/zh/docs/latest/ograc/about_ograc/product_architecture/architecture_description.html).

## Engineering Description

-   Programming language: C
-   Compilation project: CMake (recommended) or Make
-   Directories:

|Directory  | Description |
|---|---|
|build | Scripts for compiling and deploying the oGRAC database.|
|og_om | Installation and deployment scripts.|
|docker | Scripts related to building and starting oGRAC container images.|
|library | Third-party header files required for the compilation process.|
|pkg | The oGRAC source code directory. Subdirectories represent functional modules.|

## Compilation Guide

1. System initialization

    Disable SELinux and the firewall.

    ```shell
    setenforce 0
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    systemctl stop firewalld
    systemctl disable firewalld
    ```

2. Create directories and users.

    ```shell
    mkdir -p compile_path
    chmod 755 -R compile_path
    useradd user_name
    passwd user_password
    chown -R user_name:user_name compile_path
    ```

3. Install necessary dependencies.

    ```shell
    yum install -y libaio-devel openssl openssl-devel ndctl-devel \
    ncurses ncurses-devel libtirpc-devel expect ant bison iputils \
    iproute wget make gcc gcc-c++ gdb gdb-gdbserver python3 python3-devel \
    git net-tools cmake automake byacc libtool --skip-broken
    ```

4. Obtain the source code.

    ```shell
    chmod 755 -R compile_path
    cd compile_path
    git clone https://gitcode.com/opengauss/oGRAC.git
    ```

5. Modify the configuration.

    To disable the virtual memory protection option (recommended if you are compiling a debug version):
    
    ```shell
    cd oGRAC/build
    sed -i 's/DUSE_PROTECT_VM=ON/DUSE_PROTECT_VM=OFF/g' Makefile.sh
    ```

6. Compile.

    ```shell
    cd build
    sh local_install.sh prepare
    sh local_install.sh compile -b debug
    ```
    
    - `-b, --build_type=<type>` specifies the compilation type: release (default) or debug.

7. Output directory.

    The generated output package is located at `oGRAC/oGRAC-DATABASE-*-64bit`.

## Container-based Installation Guide

1. Download the Docker image.

    ```shell
    wget https://repo.openeuler.org/openEuler-22.03-LTS/docker_img/aarch64/openEuler-docker.aarch64.tar.xz
    
    docker load < ./openEuler-docker.aarch64.tar.xz
    ```

2. Start Docker.

    ```shell
    docker run --name mirror_name -itd -v /home/uer_name/docker/data:/home --privileged=true --network=host --shm-size=128g IMAGE_ID
    ```
    
    - -`v`: Mounts a host directory to the container. In this example, `/home/uer_name/docker/data` is mounted to `/home` inside the container.
    - --`shm-size`: Sets the shared memory size. It is advised to set this to 128 GB or higher.
    - `IMAGE_ID`: ID of the Docker image, which can be found by running `docker images`.

3. Configuration in the Docker image.

    Install necessary dependencies:
    ```shell
    yum install -y git unzip vim
    ```

4. View the image file.

    Run the following command as the `root` user:
    
    ```shell
    docker images
    ```
    
    You should see output similar to the following:
    
    ```shell
    REPOSITORY    TAG        TMAGE ID        CREATED                 SIZE
    mirror_name   latest    xxxx            About a minute ago      3.71GB
    ```

5. Create and access a new container.

    ```shell
    docker run -it --name=mirror_namenode mirror_name /bin/bash
    
    --`name=mirror_namenode` indicates the name of the specified container.
    
    `mirror_name` indicates the image used for instantiation.
    ```

6. Compiling oGRAC in the container.

    Download the source code:
 
    ```shell
     git clone https://gitcode.com/opengauss/oGRAC.git
    ```
 
    Modify `Makefile.sh`:
    
    ```shell
    sed -i 's+USE_PROTECT_VM=ON+USE_PROTECT_VM=OFF+' Makefile.sh
    ```

7. Compile and install oGRAC.

    Run the following commands in the `build` directory. The example below builds the debug version. Omit `-b` to build the release version by default. The `-u` flag specifies the target installation user.
    
    ```shell
    sh local_install.sh prepare
    
    sh local_install.sh compile -b debug
    
    sh local_install.sh install -u user_name
    ```

## Documentation

For more installation guides, tutorials, and API references, see [Documentation](https://docs.opengauss.org/zh/docs/latest/ograc/about_ograc/product_description/ograc_overview.html).

## Download

[Download](https://download-opengauss.osinfra.cn/archive_test/oGRAC/) to experience oGRAC.

## Community

### Governance

Check how openGauss implements open [governance](https://gitcode.com/opengauss/community/blob/master/governance.md).

### Communication

- Online communication: https://opengauss.org/en/community/onlineCommunication/
- Community forum: https://discuss.opengauss.org/

## Contributions

openGauss welcomes contributions from everyone. For details, see [Contribution](https://opengauss.org/en/contribution/).

## License

[MulanPSL-2.0](http://license.coscl.org.cn/MulanPSL2)
