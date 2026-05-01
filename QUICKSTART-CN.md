# oGRAC 数据库快速入门指南

本指南提供了操作 oGRAC 集群数据库环境所需的基本命令和序列。

## ⚠️ 重要前提条件

所有数据库操作必须由专用数据库管理员账户执行。本指南假设该账户为 `ogracdba`，且您正在该账户的 shell 会话中操作。

**不要使用 `sudo`** 运行这些命令，因为 `sudo` 会清除数据库脚本所需的环境变量（`$OGDB_HOME` 和 `$OGDB_DATA`）。

如果您以不同用户身份登录，请在继续之前切换到 `ogracdba`：

```bash
su - ogracdba
```

## 🚀 快速开始

### 1. 登录到数据库服务器

使用 SSH 或您的首选方式连接到 oGRAC 数据库服务器：

```bash
ssh ogracdba@your-server-ip
# 或如果使用不同的用户：
ssh your-user@your-server-ip
su - ogracdba
```

### 2. 验证环境设置

在开始之前，请确保您的管理员环境变量已加载。这些变量告诉数据库脚本 oGRAC 安装目录和数据目录的位置。

```bash
source ~/.bashrc
echo $OGDB_HOME  # 应该显示您的安装目录
echo $OGDB_DATA  # 应该显示您的数据目录
```

如果任一变量为空，请确认您正在以 `ogracdba` 身份运行，且您的配置文件包含正确的路径。

## 🏗️ 启动数据库集群

由于 oGRAC 作为集群运行，您必须在启动数据库引擎之前将集群管理服务（CMS）联机。

### 步骤 1：启动集群管理器

导航到您的安装目录并启动 CMS。这将挂载投票磁盘并注册节点。

```bash
cd $OGDB_HOME
sh installdb.sh -P cms
```

**预期输出：**
```
Starting cms...
cms started successfully
```

### 步骤 2：启动数据库引擎

在后台运行 `ogracd` 守护进程，将其指向您的数据目录：

```bash
ogracd -D $OGDB_DATA &
```

*等待几秒钟，直到在终端输出中看到 `instance started`。*

### 步骤 3：验证集群状态

检查 CMS 和数据库实例是否都在运行：

```bash
ps aux | grep -E "(cms|ogracd)" | grep -v grep
```

## 🔌 连接到数据库

您可以使用 `ogsql` 命令行客户端连接到本地实例。作为数据库所有者，您可以以 `sysdba` 权限登录，无需密码：

```bash
ogsql / as sysdba
```

**预期输出：**
```
oGRAC SQL>
```

## 🔍 基本 SQL 命令

连接到 `oGRAC SQL>` 提示符后，您可以使用以下查询来监控数据库的运行状况和配置。

### 实例和集群健康状况

```sql
-- 查看当前数据库状态
SELECT NAME, STATUS, OPEN_STATUS FROM DV_DATABASE;

-- 查看实例详情
SELECT INSTANCE_NAME, HOST_NAME, VERSION, STATUS FROM DV_INSTANCE;

```

### 检查配置和网络

oGRAC 使用标准的 `SHOW` 命令管理参数。

```sql
-- 显示特定参数
SHOW PARAMETER LSNR;
SHOW PARAMETER INTERCONNECT;

-- 查看所有活动参数
SHOW ALL;

```

### 监控存储和用户

```sql
-- 列出表空间及其状态
SELECT ID, NAME, FILE_COUNT, STATUS, EXTENT_MANAGEMENT FROM DV_TABLESPACES;

-- 列出数据库用户及其状态
SELECT USERNAME, ACCOUNT_STATUS, TEMPORARY_TABLESPACE FROM DV_USERS;

-- 检查数据文件状态
SELECT FILE_NAME, STATUS, BYTES/1024/1024 "SIZE_MB" FROM DV_DATA_FILES;
```

### 性能监控

```sql
-- 查看活动会话
SELECT * FROM DV_SESSIONS WHERE STATUS = 'ACTIVE';

-- 检查锁
SELECT * FROM DV_LOCKS;

-- 监控重做日志文件
SELECT * FROM DV_LOG_FILES;
```

## 📊 基本数据库操作

### 创建测试用户和数据库

```sql
-- 创建一个符合要求的密码的测试用户
CREATE USER test_user IDENTIFIED BY 'SecurePass123!';

-- 授予必要的权限
GRANT CONNECT, RESOURCE TO test_user;

-- 创建测试表
CREATE TABLE test_user.test_table (
    id NUMBER PRIMARY KEY,
    name VARCHAR2(100),
    created_date DATE DEFAULT SYSDATE
);

-- 插入测试数据
INSERT INTO test_user.test_table (id, name) VALUES (1, 'Test Record 1');
INSERT INTO test_user.test_table (id, name) VALUES (2, 'Test Record 2');

-- 查询数据
SELECT * FROM test_user.test_table;

-- 清理
DROP TABLE test_user.test_table;
DROP USER test_user CASCADE;
```

## 🛑 安全关闭

不要直接杀死 `ogracd` 进程。使用提供的关闭脚本以确保内存安全刷新到磁盘，并且事务被回滚或提交。

从标准 Linux 终端运行此命令（不在 `ogsql` 内部）：

```bash
sh $OGDB_HOME/shutdowndb.sh -h <host_ip> -p 1611 -w -m IMMEDIATE -D $OGDB_DATA
```

使用实际的数据库主机地址替换 `<host_ip>`。例如：

```bash
sh $OGDB_HOME/shutdowndb.sh -h 127.0.0.1 -p 1611 -w -m IMMEDIATE -D $OGDB_DATA
sh $OGDB_HOME/shutdowndb.sh -h 192.168.2.100 -p 1611 -w -m IMMEDIATE -D $OGDB_DATA
```

**关闭选项：**
- `-m IMMEDIATE`：强制进行立即安全关闭（推荐）
- `-m NORMAL`：等待用户优雅地断开连接
- `-m ABORT`：紧急崩溃停止（仅在必要时使用）

**同时停止 CMS：**
```bash
sh $OGDB_HOME/installdb.sh -P cms -stop
```

## 💡 故障排除

### 缺少环境变量
如果脚本抱怨缺少 `$OGDB_HOME`，请验证您没有使用 `sudo` 并运行：
```bash
source ~/.bashrc
```

### SQL 提示符卡住
如果您的 `oGRAC SQL>` 提示符忽略 `exit;` 命令或 `Ctrl+C`，您可能有未关闭的字符串。键入 `';` 并按 Enter 以触发语法错误并释放缓冲区，或按 **`Ctrl + D`** 强制退出 SQL 客户端。

### 连接问题
- 验证 CMS 正在运行：`ps aux | grep cms`
- 检查数据库状态：`ogsql / as sysdba`，然后 `SELECT STATUS FROM DV_DATABASE;`
- 查看日志：`tail -f $OGDB_DATA/log/ogracd.log`

### 权限问题
- 确保您以正确的用户身份运行（`ogracdba`）
- 检查文件权限：`ls -la $OGDB_HOME $OGDB_DATA`
- 验证用户所有权：`id` 并与文件所有权进行比较

### 集群问题
- 验证投票磁盘：`crsctl query css votedisk`
- 查看 CMS 日志：`tail -f $OGDB_DATA/log/cms.log`

## 📚 其他资源

- **官方文档**：参考 oGRAC 数据库管理员指南
- **日志文件**：所有日志存储在 `$OGDB_DATA/log/` 中
- **配置文件**：数据库配置在 `$OGDB_DATA/cfg/` 中
- **备份脚本**：位于 `$OGDB_HOME/bin/` 中

## 🔒 安全最佳实践

- 始终为数据库用户使用强密码
- 定期轮换管理员密码
- 限制只有授权人员才能直接访问数据库
- 监控审计日志以查看可疑活动
- 保持系统和数据库软件的更新

---

**注意**：本指南假设标准的 oGRAC 安装。您的具体配置可能因部署要求而异。
