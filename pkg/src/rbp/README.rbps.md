# RBPS lightweight management

`rbps` is an independent RBP cache server. In CMS deployments it can also be
started, stopped, and checked as the `rbps` CMS resource.

## Start server

```sh
rbps_ctl start
rbps_ctl status
rbps_ctl stats
rbps_ctl window
rbps_ctl stop
```

`rbps` is built with the normal oGRAC server build. The package includes `rbps` and
`rbps_ctl` and `rbps_contrl.sh` under `bin/`, plus `rbps.conf` under `cfg/`. During appctl install,
`rbps.conf` follows `ogracd.ini` into the data `cfg/` directory.
`rbps` can be managed independently with `rbps_ctl`, or through CMS with
`cms res -start rbps`, `cms res -stop rbps`, and `cms stat -res rbps` when
`USE_RBP=TRUE`.

Server-side settings live in `rbps.conf`:

```ini
HOST=0.0.0.0
PORT=2611
ADMIN_HOST=127.0.0.1
ADMIN_PORT=2711
LOG_FILE=/usr2/ograc/log/rbps/rbps.log
PID_FILE=$OGDB_HOME/run/rbps.pid
MAX_CACHE_PAGES=0
CAPACITY_EVICT_ON_WRITE=false
READ_END_MODE=async
READ_PHASE_TIMEOUT=3
```

When installed under `OGDB_HOME=/usr2/ograc/ograc/server`, the RBPS log path is
derived as `dirname(dirname($OGDB_HOME))/log/rbps/rbps.log`.

`READ_PHASE_TIMEOUT` is in seconds. A positive value automatically releases an orphan READ_PHASE after this idle
time; completed PAGE_READ/BATCH_READ/META activity refreshes the timer, while an in-flight read that exceeds the
timeout is treated as a failed/stale read phase. `0` disables the timeout release.

`MAX_CACHE_PAGES=0` disables the cache page cap. With a positive cap, `CAPACITY_EVICT_ON_WRITE=false` keeps a hard
cap: new cache pages are rejected while the cache is full, until checkpoint/reset purge frees space. Set
`CAPACITY_EVICT_ON_WRITE=true` to allow writes past the cap and evict older pages in the background.

Use `rbps_ctl` for admin queries instead of manual `nc`:

```sh
rbps_ctl exists 1-100
rbps_ctl dump 1-100
rbps_ctl query WINDOW
rbps_ctl read_phase
rbps_ctl force_read_end
```

## Enable client

RBP is off by default. CMS may pre-register the `rbps` resource, but
`USE_RBP=FALSE` keeps it disabled: it is hidden from `cms res -list` and
`cms stat`, cannot be started with `cms res -start rbps`, and is skipped by CMS
check/restart logic. Enable it explicitly in `ogracd.ini` before managing it
from CMS:

```ini
USE_RBP=TRUE
RBP_FOR_RECOVERY=TRUE
RBP_IP=127.0.0.1
RBP_PORT=2611
LOCAL_RBP_HOST=127.0.0.1
```

In a cluster, run one `rbps` per node and configure `RBP_IP` with the node RBPS address list.
