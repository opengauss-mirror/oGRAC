# GBPS lightweight management

`gbps` is an independent GBP cache server. It is not started or stopped by `ogracd`.

## Start server

```sh
gbps_ctl start
gbps_ctl status
gbps_ctl stats
gbps_ctl window
gbps_ctl stop
```

`gbps` is built with the normal oGRAC server build. The package includes `gbps` and
`gbps_ctl` under `bin/`, plus `gbps.conf` under `cfg/`. During appctl install,
`gbps.conf` follows `ogracd.ini` into the data `cfg/` directory.
`gbps` is managed independently with `gbps_ctl`; it is not bound to the
`ogracd` appctl lifecycle.

Server-side settings live in `gbps.conf`:

```ini
HOST=0.0.0.0
PORT=2611
ADMIN_HOST=127.0.0.1
ADMIN_PORT=2711
LOG_FILE=$OGDB_HOME/log/gbps/gbps.rlog
PID_FILE=$OGDB_HOME/run/gbps.pid
```

Use `gbps_ctl` for admin queries instead of manual `nc`:

```sh
gbps_ctl exists 1-100
gbps_ctl dump 1-100
gbps_ctl query WINDOW
```

## Enable client

GBP is off by default. Enable it explicitly in `ogracd.ini` after `gbps` is running:

```ini
USE_GBP=TRUE
GBP_FOR_RECOVERY=TRUE
GBP_IP=127.0.0.1
GBP_PORT=2611
LOCAL_GBP_HOST=127.0.0.1
```

In a cluster, run one `gbps` per node and configure `GBP_IP` with the node GBPS address list.
