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

1. Login to the Server

    Log in to the server where you want to perform the installation.

2. Create Installation Directory

    Create a directory in `/opt/oGRAC` with the `-p` flag:

    ```shell
    mkdir -p /opt/oGRAC
    ```

3. Set Directory Permissions

    Change the permissions recursively on the directory:

    ```shell
    chmod 755 -R /opt/oGRAC
    cd /opt/oGRAC
    ```

4. Install Git

    Install git on your system:

    ```shell
    yum install -y git
    ```

5. Clone the Repository

    Clone the oGRAC repository:

    ```shell
    git clone https://github.com/victor-akande/oGRAC.git
    ```

6. Enter the Directory

    ```shell
    cd oGRAC
    ```

7. Initialize Compilation Environment

    You have two options:

    **Option A: Interactive Initializer**
    
    Run the interactive initializer script:

    ```shell
    bash init.sh
    ```

    The script will:
    - disable SELinux and firewall if requested
    - create and configure the compile directory
    - create the compilation user and set its password
    - install necessary dependencies

    **Option B: Full Compilation and Installation**
    
    Alternatively, to perform the full compilation and installation flow in one step, run:

    ```shell
    bash full_build_install.sh
    ```

8. Configuration Modification (Optional)

    If you need to disable the protect virtual memory option (especially for debug version compilation):
    
    ```shell
    cd oGRAC/build
    sed -i 's/DUSE_PROTECT_VM=ON/DUSE_PROTECT_VM=OFF/g' Makefile.sh
    ```

9. Compile

    ```shell
    cd build
    sh local_install.sh prepare
    sh local_install.sh compile -b debug
    ```
    
    - `-b, --build_type=<type>`: Specify compile type (release/debug, default release)

10. Output Directory

    Output package located at: `oGRAC/oGRAC-DATABASE-*-64bit`

11. Switch to Database Admin User and Follow QUICKSTART Guide

    Once the installation is complete, switch to the database admin user and follow the [QUICKSTART Guide](./QUICKSTART.md) for next steps.

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