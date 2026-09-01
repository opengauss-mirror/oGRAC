# Offline in-place restore

`ogbackup --offline-restore --backup-dir=<local backupset directory> --in-place --force`
restores physical files to the original paths recorded by the selected chain's final control image. The backupset
source must be a local filesystem directory. `--in-place` rejects `--target-dir`; path remapping, a new DSS VG,
PITR, resume and parallel restore workers are not supported. Use `--password-file` (a mode `0600` regular file)
instead of exposing an encryption password in process arguments.

Before any database target is changed, the command validates the complete full/differential or full/cumulative
chain, orders and checks all parallel backup sections, authenticates every AES-256-GCM payload, decodes all
protected LZ4/AES payloads, parses the final control image, freezes the local/DSS write plan, checks duplicate and
conflicting targets, and prints the plan. All `ogracd` and CMS server processes must be stopped. Local restore does
not depend on DSS. DSS restore requires exactly one `dssserver`, a usable `DSS_HOME` UDS provider and original
`+vg/...` targets.

Datafile, redo and `CONTROL_FILES` targets come directly from the final control image. The backup catalog's
`bak_file_t` does not persist an archive destination path. Matching archive ring entries therefore keep their
recorded original path; for a backup archive not yet present in that ring, the tool mirrors online restore by
reading `ARCHIVE_DEST_1` and `ARCHIVE_FORMAT` from `OGDB_DATA/cfg/ogracd.ini`, then validates the decoded archive
header's ASN/resetlogs values before deriving the target. A missing, relative or storage-mismatched destination
fails before mutation.

Mutation uses fail-stop markers in the local backup directory. `in-progress` is durable before target preparation;
failures before that marker leave no marker, while any later failure replaces it with `failed`. `--force`
restarts from scratch by preparing every planned target again and never resumes or skips prior partial work.
Datafiles, redo and archive payloads are created/truncated, restored in chain and section order, fsynced and closed
first. The validated control image is committed to every original
`CONTROL_FILES` path only after those non-control files succeed. The final durable marker is
`.ogbackup_offline_restore_file_phase_complete` with `status=FILE_PHASE_COMPLETE`.

This command restores redo/archive files but does not apply redo, start `ogracd`, operate CMS/DSS services, execute
`RECOVER DATABASE`, choose `RESETLOGS`, or open the database. After `FILE_PHASE_COMPLETE`, an operator must start
the database through the established maintenance workflow, let the kernel perform recovery, and validate `OPEN`,
tables, indexes and application data.

## Required environment validation matrix

- local and DSS level-0/full restore, including missing control/data/redo objects and wrong-sized objects;
- full plus differential and full plus cumulative chains;
- online parallel backup pieces, plus missing, duplicate, overlapping and out-of-range sections;
- plain, LZ4, AES-256-GCM and LZ4 plus AES-256-GCM payloads;
- wrong password and damaged ciphertext before any target mutation;
- invalid parent/identity/resetlogs/LSN chains and archive gaps;
- injected failure before control commit, verifying no formal control copy is written;
- interrupted restore and `--force` from-scratch retry;
- database kernel recovery followed by `OPEN` and logical data/index checks.
