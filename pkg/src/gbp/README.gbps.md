# GBPS lightweight management

`gbps` is an independent GBP cache server. In CMS deployments it can also be
started, stopped, and checked as the `gbps` CMS resource.

## Start server

```sh
gbps_ctl start
gbps_ctl status
gbps_ctl stats
gbps_ctl window
gbps_ctl stop
```

`gbps` is built with the normal oGRAC server build. The package includes `gbps` and
`gbps_ctl` and `gbps_contrl.sh` under `bin/`, plus `gbps.conf` under `cfg/`. During appctl install,
`gbps.conf` follows `ogracd.ini` into the data `cfg/` directory.
`gbps` can be managed independently with `gbps_ctl`, or through CMS with
`cms res -start gbps`, `cms res -stop gbps`, and `cms stat -res gbps` when
`USE_GBP=TRUE`.

Server-side settings live in `gbps.conf`:

```ini
HOST=0.0.0.0
PORT=2611
ADMIN_HOST=127.0.0.1
ADMIN_PORT=2711
LOG_FILE=/usr2/ograc/log/gbps/gbps.log
PID_FILE=$OGDB_HOME/run/gbps.pid
MAX_CACHE_PAGES=0
CAPACITY_EVICT_ON_WRITE=false
READ_END_MODE=async
READ_PHASE_TIMEOUT=3
```

When installed under `OGDB_HOME=/usr2/ograc/ograc/server`, the GBPS log path is
derived as `dirname(dirname($OGDB_HOME))/log/gbps/gbps.log`.

`READ_PHASE_TIMEOUT` is in seconds. A positive value automatically releases an orphan READ_PHASE after this idle
time; completed PAGE_READ/BATCH_READ/META activity refreshes the timer, while an in-flight read that exceeds the
timeout is treated as a failed/stale read phase. `0` disables the timeout release.

`MAX_CACHE_PAGES=0` disables the cache page cap. With a positive cap, `CAPACITY_EVICT_ON_WRITE=false` keeps a hard
cap: new cache pages are rejected while the cache is full, until checkpoint/reset purge frees space. Set
`CAPACITY_EVICT_ON_WRITE=true` to allow writes past the cap and evict older pages in the background.

Use `gbps_ctl` for admin queries instead of manual `nc`:

```sh
gbps_ctl exists 1-100
gbps_ctl dump 1-100
gbps_ctl query WINDOW
gbps_ctl read_phase
gbps_ctl force_read_end
```

## Enable client

GBP is off by default. CMS may pre-register the `gbps` resource, but
`USE_GBP=FALSE` keeps it disabled: it is hidden from `cms res -list` and
`cms stat`, cannot be started with `cms res -start gbps`, and is skipped by CMS
check/restart logic. Enable it explicitly in `ogracd.ini` before managing it
from CMS:

```ini
USE_GBP=TRUE
GBP_FOR_RECOVERY=TRUE
GBP_IP=127.0.0.1
GBP_PORT=2611
LOCAL_GBP_HOST=127.0.0.1
```

In a cluster, run one `gbps` per node and configure `GBP_IP` with the node GBPS address list.
