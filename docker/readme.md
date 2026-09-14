# 容器开发编译部署手册

详情可以参考[oGRAC容器单节点部署指引](https://docs.opengauss.org/zh/docs/latest/ograc/installation_guide/single_node_guide/containerized_single_node_installation.html)。

仓库内推荐用 `docker/Dockerfile_ARM64`（aarch64）构建镜像，再用下面的 `docker run` 启动。命令可直接复制。

## 构建镜像

在**仓库根目录**执行：

```shell
# aarch64 / openEuler 22.03
docker build -f docker/Dockerfile_ARM64 -t ograc-dev .
```

> * **基础镜像拉取失败的处理**：`Dockerfile_ARM64` 的 `FROM openeuler/openeuler:22.03-lts-sp1` 默认从 Docker Hub 拉取。若所在网络 Docker Hub 不可达（报 `net/http request canceled` 等超时），且本机已有等价基础镜像（例如本地 `openeuler-22.03-lts-sp1`），可将其打标签为 Dockerfile 所需名称后直接复用缓存层构建：
> ```shell
> docker tag openeuler-22.03-lts-sp1 openeuler/openeuler:22.03-lts-sp1
> docker build -f docker/Dockerfile_ARM64 -t ograc-dev .
> ```
> 也可将 `Dockerfile_ARM64` 的 `FROM` 改为内网可达的镜像仓库地址后再构建。

## 启动容器（推荐）

将源码挂到容器内 `/home/regress/ogracKernel`，并单独挂载 `ograc_data`（CMS 的 `gcc_home` 写在这里）。`--shm-size` 建议至少 16g，且不超过宿主机物理内存。

```shell
REPO_DIR=$(pwd)
DATA_DIR="$(dirname "${REPO_DIR}")/ograc_data"
mkdir -p "${DATA_DIR}"

docker run -d --privileged --network=host --shm-size=16g \
  --name ograc-dev \
  -v "${REPO_DIR}":/home/regress/ogracKernel \
  -v "${DATA_DIR}":/home/regress/ograc_data \
  ograc-dev
```

进入该容器：

```shell
docker exec -it ograc-dev bash
```

镜像已将 `/home/regress` 设为 755，并预创建 `/home/regress/ograc_data/gcc_home`。

## 容器内编译与测试

仓库根目录为 `/home/regress/ogracKernel`。compile 不会生成 `og_regress`，须先 `make` 再跑测试，**不要**加 `need_compile`。

```shell
cd /home/regress/ogracKernel
cd build
sh local_install.sh compile -b release
source ./common.sh
strip -N main "${OGRACDB_OUTPUT}/lib/libogserver.a"
cd pkg/test/og_regress
make -sj 8
cd "${CODE_HOME_PATH}"
# 必须在编译完成后执行：编译会重置产物权限
chmod -R 777 .
bash pkg/test/og_regress/do_all_test.sh
```

> * **一体化验证（推荐）**：若同时需要构建验证、单元测试与样例部署，可用 `sh Makefile.sh make_ograc_pkg_test`（Debug+test 变体）一次产出主程序、安装包与 `og_regress`，省去上面的 `compile -b release` 与 `make -sj 8` 两步；随后在仓库根目录先 `chmod -R 777 .`（必须在构建完成后执行，构建会重置产物权限）再执行 `do_all_test.sh` 跑单元测试。脚本内部自动完成安装、SQL 用例验证与卸载（即同时覆盖样例验证），**不要**再按 README「安装流程」手动部署样例。

从未编译过、且没有 `output/bin` 产物时，才使用：

```shell
bash pkg/test/og_regress/do_all_test.sh need_compile
```

## 另一套入口：container.sh

`sh docker/container.sh rundev` 使用另一套默认值，**不要**和上面的 `ograc-dev` 混用：

- 容器名：`cantian_dev-dev`
- `--shm-size 10240M`
- 进入：`sh docker/container.sh enterdev`

该脚本会调用 `docker/init_container.sh` 创建 `ogracdba` 并准备 `ograc_data`。

## 说明

- 容器内安装会把 `gcc_home` 软链到 `/home/regress/ograc_data/gcc_home`。若手建容器，请保证该路径对运行用户可写，且 `/home/regress` 为 755（或更宽）。
- 官方文档中的 `--shm-size=128g` 在内存不足的机器上无法设置，请按宿主机内存下调（推荐路径验证过 16g 可启动 CMS）。
