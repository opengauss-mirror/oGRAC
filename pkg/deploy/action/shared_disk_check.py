#!/usr/bin/env python3
"""Shared disk (LUN) pre-check for the DSS deploy mode.

The configured ``gcc_home`` / ``dss_vg_list`` entries may be symlinks (udev
aliases, /dev/disk/by-id, /dev/mapper, ...). Every entry must finally resolve
to a block device under /dev, and the deploy user must be able to read/write
it because DSS initializes the volumes with ``dd`` as that user.

Only the standard library is used so this module can be imported from the
root action dir as well as from cms/ and dss/. Every check is read-only.
"""

import os
import stat

REQUIRED_VGS = ("vg1", "vg2", "vg3")
OPTIONAL_VGS = ("vg4",)
SUPPORTED_VGS = REQUIRED_VGS + OPTIONAL_VGS
MAX_LINK_DEPTH = 16
DEV_PREFIX = "/dev/"


class SharedDiskCheckError(RuntimeError):
    """Raised when a configured shared disk is unusable."""


def _is_abs_path(value):
    return isinstance(value, str) and value.strip() != "" and os.path.isabs(value)


def validate_disk_params(params):
    """Config-level checks without touching any device. Returns error messages."""
    errors = []

    gcc_home = params.get("gcc_home")
    if not _is_abs_path(gcc_home):
        errors.append("gcc_home must be an absolute device path, got %r" % (gcc_home,))

    vg_list = params.get("dss_vg_list")
    if not isinstance(vg_list, dict) or not vg_list:
        errors.append("dss_vg_list must be a non-empty JSON object")
        return errors

    missing = [vg for vg in REQUIRED_VGS if vg not in vg_list]
    if missing:
        errors.append("dss_vg_list is missing required volume group(s): %s" % ", ".join(missing))
    unknown = sorted(str(key) for key in vg_list if key not in SUPPORTED_VGS)
    if unknown:
        errors.append("dss_vg_list has unsupported volume group(s): %s (only %s are supported)"
                      % (", ".join(unknown), ", ".join(SUPPORTED_VGS)))
    for vg, path in vg_list.items():
        if not _is_abs_path(path):
            errors.append("dss_vg_list.%s must be an absolute device path, got %r" % (vg, path))
    return errors


def resolve_block_device(label, configured):
    """Follow symlinks step by step; the target must be a block device under /dev.

    Returns (final_path, stat_result, chain). The full symlink chain is kept in
    the error message so a broken link is easy to locate.
    """
    if not _is_abs_path(configured):
        raise SharedDiskCheckError("[%s] %r is not an absolute path" % (label, configured))

    chain = [configured]
    path = configured
    while os.path.islink(path):
        if len(chain) > MAX_LINK_DEPTH:
            raise SharedDiskCheckError(
                "[%s] symlink chain too deep or circular: %s" % (label, " -> ".join(chain)))
        target = os.readlink(path)
        path = os.path.normpath(os.path.join(os.path.dirname(path), target))
        chain.append(path)

    chain_text = " -> ".join(chain)
    if not os.path.exists(path):
        raise SharedDiskCheckError(
            "[%s] device does not exist (dangling symlink, udev/multipath rule not applied): %s"
            % (label, chain_text))
    st = os.stat(path)
    if not stat.S_ISBLK(st.st_mode):
        raise SharedDiskCheckError(
            "[%s] %s is not a block device (regular file, directory or char device)"
            % (label, chain_text))
    if not path.startswith(DEV_PREFIX):
        raise SharedDiskCheckError(
            "[%s] final device %s is not under %s" % (label, path, DEV_PREFIX))
    return path, st, chain


def assert_block_device(path, label):
    """Guard to call right before dd: refuse anything that is not a real block device."""
    return resolve_block_device(label, path)[0]


def _user_identity(user):
    import pwd  # POSIX only, imported lazily

    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        raise SharedDiskCheckError("deploy user %s does not exist" % user)
    return pw.pw_uid, set(os.getgrouplist(user, pw.pw_gid))


def user_can_rw(st, uid, gids):
    """Whether the user may open the device node read+write, judged by owner/group/mode.

    os.access() is useless here: the pre-check runs as root, for whom it is always True.
    """
    mode = st.st_mode
    if st.st_uid == uid:
        return bool(mode & stat.S_IRUSR) and bool(mode & stat.S_IWUSR)
    if st.st_gid in gids:
        return bool(mode & stat.S_IRGRP) and bool(mode & stat.S_IWGRP)
    return bool(mode & stat.S_IROTH) and bool(mode & stat.S_IWOTH)


def _format_owner(st):
    return "uid=%d gid=%d mode=%s" % (st.st_uid, st.st_gid, oct(stat.S_IMODE(st.st_mode)))


def run_shared_disk_check(params, user, logger=None):
    """Validate gcc_home and every dss_vg_list entry before anything touches them.

    Checks: params are well-formed, each path resolves to a block device under
    /dev, no two entries point at the same device, and ``user`` can read/write
    the device node. The permission problem is a hard error for DSS volume
    groups (dss_ctl.py runs dd as that user) but only a warning for gcc_home
    (cms_deploy.py zeroes and chowns it as root).

    Raises SharedDiskCheckError listing every problem found.
    """
    errors = validate_disk_params(params)
    if errors:
        raise SharedDiskCheckError("shared disk config check failed:\n" + "\n".join(errors))

    uid, gids = _user_identity(user)
    devices = [("gcc_home", params["gcc_home"])] + list(params["dss_vg_list"].items())
    seen = {}
    results = []
    for label, configured in devices:
        try:
            final, st, chain = resolve_block_device(label, configured)
        except SharedDiskCheckError as error:
            errors.append(str(error))
            continue

        rdev = (os.major(st.st_rdev), os.minor(st.st_rdev))
        if rdev in seen:
            errors.append("[%s] %s points to the same device %s as %s"
                          % (label, configured, final, seen[rdev]))
        else:
            seen[rdev] = label

        owner = _format_owner(st)
        if not user_can_rw(st, uid, gids):
            message = ("[%s] user %s has no read/write permission on %s (%s); "
                       "set OWNER/GROUP/MODE for the device in a udev rule"
                       % (label, user, final, owner))
            if label == "gcc_home":
                if logger:
                    logger.warning("%s (cms install chowns it as root, but the udev rule "
                                   "is still needed after reboot)", message)
            else:
                errors.append(message + ", otherwise DSS lun init (dd) will fail")

        if logger:
            logger.info("[Check Item]-[shared disk]: [%s] %s  dev=%d:%d  %s",
                        label, " -> ".join(chain), rdev[0], rdev[1], owner)
        results.append({"label": label, "configured": configured, "device": final, "rdev": rdev})

    if errors:
        raise SharedDiskCheckError("shared disk check failed:\n" + "\n".join(errors))
    return results
