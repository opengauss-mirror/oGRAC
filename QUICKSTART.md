# oGRAC Database Quick Start Guide

This guide provides the essential commands and sequences required to operate the oGRAC clustered database environment.

## ⚠️ Important Prerequisites

All database operations must be performed by the dedicated database administrator account. This guide assumes that account is `ogracdba` and that you are using its shell session.

**DO NOT use `sudo`** to run these commands, as `sudo` clears the environment variables (`$OGDB_HOME` and `$OGDB_DATA`) required by the database scripts.

If you are logged in as a different user, switch to `ogracdba` before proceeding:

```bash
su - ogracdba
```

## 🚀 Getting Started

### 1. Log into the Database Server

Connect to your oGRAC database server using SSH or your preferred method:

```bash
ssh ogracdba@your-server-ip
# Or if using a different user:
ssh your-user@your-server-ip
su - ogracdba
```

### 2. Verify Environment Setup

Before starting, ensure your administrator environment variables are loaded. These variables tell the database scripts where the oGRAC installation and data directories live.

```bash
source ~/.bashrc
echo $OGDB_HOME  # Should show your install directory
echo $OGDB_DATA  # Should show your data directory
```

If either variable is empty, confirm you are running as `ogracdba` and that your profile contains the correct paths.

## 🏗️ Starting the Database Cluster

Because oGRAC operates as a cluster, you must bring the Cluster Management Service (CMS) online before starting the database engine.

### Step 1: Start the Cluster Manager

Navigate to your installation directory and start the CMS. This will mount the voting disk and register the nodes.

```bash
cd $OGDB_HOME
sh installdb.sh -P cms
```

**Expected Output:**
```
Starting cms...
cms started successfully
```

### Step 2: Start the Database Engine

Run the `ogracd` daemon in the background, pointing it to your data directory:

```bash
ogracd -D $OGDB_DATA &
```

*Wait a few seconds until you see `instance started` in the terminal output.*

### Step 3: Verify Cluster Status

Check that both CMS and the database instance are running:

```bash
ps aux | grep -E "(cms|ogracd)" | grep -v grep
```

## 🔌 Connecting to the Database

You can connect to the local instance using the `ogsql` command-line client. As the database owner, you can log in with `sysdba` privileges without a password:

```bash
ogsql / as sysdba
```

**Expected Output:**
```
oGRAC SQL>
```

## 🔍 Essential SQL Commands

Once connected to the `oGRAC SQL>` prompt, you can use the following queries to monitor the health and configuration of your database.

### Instance & Cluster Health

```sql
-- View the current database status
SELECT NAME, STATUS, OPEN_STATUS FROM DV_DATABASE;

-- View instance details
SELECT INSTANCE_NAME, HOST_NAME, VERSION, STATUS FROM DV_INSTANCE;

```

### Checking Configurations & Network

oGRAC manages parameters using the standard `SHOW` command.

```sql
-- Show a specific parameter 
SHOW PARAMETER LSNR;
SHOW PARAMETER INTERCONNECT;

-- View ALL active parameters
SHOW ALL;

```

### Monitoring Storage & Users

```sql
-- List tablespaces and their status
SELECT ID, NAME, FILE_COUNT, STATUS, EXTENT_MANAGEMENT FROM DV_TABLESPACES;

-- List database users and their status
SELECT USERNAME, ACCOUNT_STATUS, TEMPORARY_TABLESPACE FROM DV_USERS;

-- Check datafile status
SELECT FILE_NAME, STATUS, BYTES/1024/1024 "SIZE_MB" FROM DV_DATA_FILES;
```

### Performance Monitoring

```sql
-- View active sessions
SELECT * FROM DV_SESSIONS WHERE STATUS = 'ACTIVE';

-- Check for locks
SELECT * FROM DV_LOCKS;

-- Monitor redo log files
SELECT * FROM DV_LOG_FILES;
```

## 📊 Basic Database Operations

### Creating a Test User and Database

```sql
-- Create a test user with a compliant password
CREATE USER test_user IDENTIFIED BY 'SecurePass123!';

-- Grant necessary privileges
GRANT CONNECT, RESOURCE TO test_user;

-- Create a test table
CREATE TABLE test_user.test_table (
    id NUMBER PRIMARY KEY,
    name VARCHAR2(100),
    created_date DATE DEFAULT SYSDATE
);

-- Insert test data
INSERT INTO test_user.test_table (id, name) VALUES (1, 'Test Record 1');
INSERT INTO test_user.test_table (id, name) VALUES (2, 'Test Record 2');

-- Query the data
SELECT * FROM test_user.test_table;

-- Clean up
DROP TABLE test_user.test_table;
DROP USER test_user CASCADE;
```

## 🛑 Safely Shutting Down

Never kill the `ogracd` process directly. Use the provided shutdown script to ensure memory is safely flushed to disk and transactions are rolled back or committed.

Run this from the standard Linux terminal (not inside `ogsql`):

```bash
sh $OGDB_HOME/shutdowndb.sh -h <host_ip> -p 1611 -w -m IMMEDIATE -D $OGDB_DATA
```

Use the actual database host address for `<host_ip>`. For example:

```bash
sh $OGDB_HOME/shutdowndb.sh -h 127.0.0.1 -p 1611 -w -m IMMEDIATE -D $OGDB_DATA
sh $OGDB_HOME/shutdowndb.sh -h 192.168.2.100 -p 1611 -w -m IMMEDIATE -D $OGDB_DATA
```

**Shutdown Options:**
- `-m IMMEDIATE`: Forces an immediate, safe shutdown (recommended)
- `-m NORMAL`: Waits for users to disconnect gracefully
- `-m ABORT`: Emergency crash-stop (use only when necessary)

**Stop CMS as well:**
```bash
sh $OGDB_HOME/installdb.sh -P cms -stop
```

## 💡 Troubleshooting

### Missing Environment Variables
If scripts complain about missing `$OGDB_HOME`, verify you aren't using `sudo` and run:
```bash
source ~/.bashrc
```

### Stuck SQL Prompt
If your `oGRAC SQL>` prompt ignores the `exit;` command or `Ctrl+C`, you likely have an unclosed string. Type `';` and hit Enter to trigger a syntax error and free the buffer, or press **`Ctrl + D`** to force-quit the SQL client.

### Connection Issues
- Verify CMS is running: `ps aux | grep cms`
- Check database status: `ogsql / as sysdba` then `SELECT STATUS FROM DV_DATABASE;`
- Review logs: `tail -f $OGDB_DATA/log/ogracd.log`

### Permission Issues
- Ensure you're running as the correct user (`ogracdba`)
- Check file permissions: `ls -la $OGDB_HOME $OGDB_DATA`
- Verify user ownership: `id` and compare with file ownership

### Cluster Issues
- Verify voting disk: `crsctl query css votedisk`
- Review CMS logs: `tail -f $OGDB_DATA/log/cms.log`

## 📚 Additional Resources

- **Official Documentation**: Refer to the oGRAC Database Administrator's Guide
- **Log Files**: All logs are stored in `$OGDB_DATA/log/`
- **Configuration Files**: Database configuration is in `$OGDB_DATA/cfg/`
- **Backup Scripts**: Located in `$OGDB_HOME/bin/`

## 🔒 Security Best Practices

- Always use strong passwords for database users
- Regularly rotate administrative passwords
- Limit direct database access to authorized personnel only
- Monitor audit logs for suspicious activity
- Keep the system and database software updated

---

**Note**: This guide assumes a standard oGRAC installation. Your specific configuration may vary based on your deployment requirements.