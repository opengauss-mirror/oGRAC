#!/usr/bin/env python3
class Constant:
    PORT = '8088'
    HTTPS = 'https://'
    LOGIN = '/deviceManager/rest/xxxxx/login'
    LOGOUT = '/deviceManager/rest/{deviceId}/sessions'
    QUERY_POOL = '/deviceManager/rest/{deviceId}/storagepool'
    CREATE_FS = '/deviceManager/rest/{deviceId}/filesystem'
    QUERY_FILE_SYSTEM_NUM = '/deviceManager/rest/{deviceId}/filesystem/count'
    DELETE_FS = '/deviceManager/rest/{deviceId}/filesystem/{id}'
    NFS_SERVICE = '/deviceManager/rest/{deviceId}/nfsservice'
    NFS_SHARE_ADD = '/deviceManager/rest/{deviceId}/NFSSHARE'
    NFS_SHARE_ADD_CLIENT = '/deviceManager/rest/{deviceId}/NFS_SHARE_AUTH_CLIENT'
    NFS_SHARE_DELETE = '/deviceManager/rest/{deviceId}/NFSSHARE/{id}'
    NFS_SHARE_DEL_CLIENT = '/deviceManager/rest/{deviceId}/NFS_SHARE_AUTH_CLIENT/{id}'
    NFS_SHARE_QUERY = '/deviceManager/rest/{deviceId}/NFSSHARE'
    QUERY_VSTORE = '/deviceManager/rest/{deviceId}/vstore/count'
    CREATE_VSTORE = '/deviceManager/rest/{deviceId}/vstore'
    DELETE_VSTORE = '/deviceManager/rest/{deviceId}/vstore/{id}'
    CREATE_LIF = "/deviceManager/rest/{deviceId}/lif"
    DELETE_LIF = "/deviceManager/rest/{deviceId}/lif?NAME={name}"
    CREATE_CLONE_FS = "/deviceManager/rest/{deviceId}/filesystem"
    SPLIT_CLONE_FS = "/deviceManager/rest/{deviceId}/clone_fs_split"
    CREATE_FSSNAPSHOT = "/deviceManager/rest/{deviceId}/fssnapshot"
    ROLLBACK_SNAPSHOT = "/deviceManager/rest/{deviceId}/fssnapshot/rollback_fssnapshot"
    QUERY_ROLLBACK_SNAPSHOT_PROCESS = "/deviceManager/rest/{deviceId}/FSSNAPSHOT/" \
                                      "query_fs_snapshot_rollback?PARENTNAME={fs_name}"
    QUERY_LOGIC_PORT_INFO = "/deviceManager/rest/{deviceId}/lif"

    QUERY_SYSTEM_INFO = "/deviceManager/rest/{deviceId}/system/"
    QUERY_REMOTE_DEVICE_INFO = "/deviceManager/rest/{deviceId}/remote_device"
    QUERY_LICENSE_FEATURE = "/deviceManager/rest/{deviceId}/license/feature"
    QUERY_HYPER_METRO_FILE_SYSTEM_PAIR = "/deviceManager/rest/{deviceId}/HyperMetroPair/associate"
    QUERY_HYPER_METRO_FILE_SYSTEM_COUNT = "/deviceManager/rest/{deviceId}/HyperMetroPair/count"
    QUERY_REPLICATION_FILE_SYSTEM_PAIR = "/deviceManager/rest/{deviceId}/replicationpair/associate"
    QUERY_FILESYSTEM_FOR_REPLICATION = "/deviceManager/rest/{deviceId}/filesystem_for_replication"

    HYPER_METRO_DOMAIN = "/deviceManager/rest/{deviceId}/FsHyperMetroDomain"
    HYPER_METRO_VSTORE_PAIR = "/deviceManager/rest/{deviceId}/vstore_pair"
    HYPER_METRO_FILESYSTEM_PAIR = "/deviceManager/rest/{deviceId}/HyperMetroPair"
    SPLIT_REMOTE_REPLICATION_FILESYSTEM_PAIR = "/deviceManager/rest/{deviceId}/REPLICATIONPAIR/split"
    SYNC_REMOTE_REPLICATION_FILESYSTEM_PAIR = "/deviceManager/rest/{deviceId}/REPLICATIONPAIR/sync"
    REMOTE_REPLICATION_FILESYSTEM_PAIR_OPT = "/deviceManager/rest/{deviceId}/REPLICATIONPAIR/{id}"
    DELETE_HYPER_METRO_PAIR = "/deviceManager/rest/{deviceId}/HyperMetroPair/{id}"
    DELETE_HYPER_METRO_VSTORE_PAIR = "/deviceManager/rest/{deviceId}/vstore_pair/{id}"
    SPLIT_FILESYSTEM_HYPER_METRO_DOMAIN = "/deviceManager/rest/{deviceId}/SplitFsHyperMetroDomain"
    DELETE_FILESYSTEM_HYPER_METRO_DOMAIN = "/deviceManager/rest/{deviceId}/FsHyperMetroDomain/{id}"
    CANCEL_SECONDARY_WRITE_LOCK = "/deviceManager/rest/{deviceId}/REPLICATIONPAIR/CANCEL_SECONDARY_WRITE_LOCK"
    SET_SECONDARY_WRITE_LOCK = "/deviceManager/rest/{deviceId}/REPLICATIONPAIR/SET_SECONDARY_WRITE_LOCK"
    SWAP_ROLE_FS_HYPER_METRO_DOMAIN = "/deviceManager/rest/{deviceId}/SwapRoleFsHyperMetroDomain"
    SWAP_ROLE_REPLICATION_PAIR = "/deviceManager/rest/{deviceId}/REPLICATIONPAIR/switch"
    CHANGE_FS_HYPER_METRO_DOMAIN_SECOND_ACCESS = "/deviceManager/rest/{deviceId}/ChangeFsHyperMetroDomainSecondAccess"
    JOIN_FS_HYPER_METRO_DOMAIN = "/deviceManager/rest/{deviceId}/JoinFsHyperMetroDomain"

    REMOTE_EXECUTE = "/api/v2/remote_execute"
    CREATE_HYPER_METRO_FILESYSTEM_PAIR = "/api/v2/task/fileSystem/HyperMetroPair"
    QUERY_TASK_PROCESS = "/api/v2/task/{id}"
    CREATE_REMOTE_REPLICATION_FILESYSTEM_PAIR = "/api/v2/task/protection/nas"
    DELETE_FS_CDP_SCHEDULE = '/deviceManager/rest/{deviceId}/filesystem/remove_associate'

    FULL_SYNC_MAX_TIME = 1500


OGRAC_DOMAIN_PREFIX = "oGRACDomain_%s%s"
SPEED = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "highest": 4
}


class HealthStatus:
    Normal = "1"
    Faulty = "2"
    Invalid = "14"


class SystemRunningStatus:
    Normal = "1"
    NotRunning = "3"
    PoweringOn = "12"
    PoweringOff = "47"
    Upgrading = "51"


class RemoteDeviceStatus:
    LinkUp = "10"
    LinkDown = "11"
    Disabled = "31"
    Connecting = "101"
    AirGapLinkDown = "118"


class ReplicationRunningStatus:
    Normal = "1"
    Synchronizing = "23"
    TobeRecovered = "33"
    Interrupted = "34"
    Split = "26"
    Invalid = "35"
    Standby = "110"


class FilesystemRunningStatus:
    Online = "27"
    Offline = "28"
    Invalid = "35"
    Initializing = "53"


class MetroDomainRunningStatus:
    Normal = "0"
    Recovering = "1"
    Faulty = "2"
    Split = "3"
    ForceStarted = "4"
    Invalid = "5"


class VstorePairRunningStatus:
    Normal = "1"
    Unsynchronized = "25"
    Split = "26"
    Invalid = "35"
    ForceStarted = "93"


class VstorePairConfigStatus:
    Normal = "0"
    Synchronizing = "1"
    Unsynchronizing = "2"


class FilesystemPairRunningStatus:
    Normal = "1"
    Synchronizing = "23"
    Invalid = "35"
    Paused = "41"
    ForceStarted = "93"
    ToBeSynchronized = "100"
    Creating = "119"


class SecresAccess:
    AccessDenied = "1"
    ReadOnly = "2"
    ReadAndWrite = "3"


class PoolStatus:
    PreCopy = "14"
    Rebuilt = "16"
    Online = "27"
    Offline = "28"
    Balancing = "32"
    Initializing = "53"
    Deleting = "106"


class PoolHealth:
    Normal = "1"
    Faulty = "2"
    Degraded = "5"


class DomainAccess:
    ReadAndWrite = "3"
    ReadOnly = "1"


class ConfigRole:
    Secondary = "0"
    Primary = "1"


class DataIntegrityStatus:
    consistent = "1"
    inconsistent = "2"


class RepFileSystemNameRule:
    NamePrefix = "og_"
    NameSuffix = "_rep"
