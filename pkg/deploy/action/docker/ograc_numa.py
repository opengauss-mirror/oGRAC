#!/usr/bin/env python3
import os
import re
import sys
import time

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, CUR_PATH)

from config import get_config

_cfg = get_config()
_paths = _cfg.paths

sys.path.append(os.path.join(CUR_PATH, ".."))

from logic.common_func import exec_popen
from delete_unready_pod import KubernetesService, get_pod_name_from_info
from om_log import LOGGER as LOG
from docker_common.file_utils import open_and_lock_json, write_and_unlock_json, LockFile

NUMA_INFO_PATH = _paths.numa_info_path
TIME_OUT = 100
MAX_CHECK_TIME = 120
CHECK_INTERVAL = 3


class CPUAllocator:
    def __init__(self):
        self.numa_info_key = "numa_info"

    @staticmethod
    def get_cpu_num():
        return int(os.getenv("MY_CPU_NUM", "0"))

    @staticmethod
    def get_hostname():
        return os.getenv("HOSTNAME", "")

    @staticmethod
    def execute_cmd(cmd):
        return_code, output, stderr = exec_popen(cmd, timeout=TIME_OUT)
        if return_code:
            err_msg = f"Execute cmd[{cmd}] failed, details:{stderr}"
            raise Exception(err_msg)
        return output

    @staticmethod
    def _parse_cpu_list(cpu_list_str):
        """Parse CPU list string (ranges and single numbers). E.g. '0-25' -> [0..25]."""
        cpu_list = []
        for part in cpu_list_str.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                cpu_list.extend(range(start, end + 1))
            else:
                cpu_list.append(int(part))
        return cpu_list

    @staticmethod
    def get_numa_info():
        cmd = "lscpu | grep -i 'NUMA node(s)'"
        return_code, stdout, stderr = exec_popen(cmd, timeout=TIME_OUT)
        if return_code:
            err_msg = f"Execute cmd[{cmd}] failed, details:{stderr}"
            raise Exception(err_msg)

        numa_nodes = int(re.search(r'\d+', stdout).group())

        cmd = "lscpu | grep -i 'NUMA node[0-9] CPU(s)'"
        return_code, stdout, stderr = exec_popen(cmd, timeout=TIME_OUT)
        if return_code:
            err_msg = f"Execute cmd[{cmd}] failed, details:{stderr}"
            raise Exception(err_msg)

        cpu_info = {}
        total_cpus = 0
        for line in stdout.splitlines():
            match = re.search(r'NUMA node(\d+) CPU\(s\):\s+([\d,\-]+)', line)
            if match:
                node = str(match.group(1))
                cpu_list_str = match.group(2)
                cpu_list = CPUAllocator._parse_cpu_list(cpu_list_str)
                node_cpus = len(cpu_list)
                total_cpus = max(total_cpus, node_cpus)
                cpu_info[node] = {
                    "available_cpus": cpu_list,
                    "available_cpu_count": node_cpus,
                    "max_cpu": max(cpu_list),
                    "min_cpu": min(cpu_list)
                }
        return total_cpus, numa_nodes, cpu_info

    def bind_cpu(self, cpus, pid=1):
        cpu_range = ",".join(map(str, cpus))
        taskset_cmd = f"taskset -cp {cpu_range} {pid}"
        cpuset_cpu_cmd = f"echo {cpu_range} > {_paths.cpuset_cpus}"

        self.execute_cmd(cpuset_cpu_cmd)
        self.execute_cmd(taskset_cmd)

    def get_numa_nodes_for_cpus(self, cpus):
        """Determine NUMA nodes for CPU list; return node range if cross-NUMA."""
        total_cpus, numa_nodes, cpu_info = self.get_numa_info()

        nodes = set()
        for cpu in cpus:
            for node, info in cpu_info.items():
                if info["min_cpu"] <= cpu <= info["max_cpu"]:
                    nodes.add(node)

        return ",".join(sorted(nodes))

    def verify_binding(self, expected_cpu_num, pid=1):
        cmd = f"taskset -cp {pid}"
        stdout = self.execute_cmd(cmd)

        match = re.search(r'list:\s+([\d,-]+)', stdout)
        if match:
            cpu_list_str = match.group(1)
            actual_cpus = self._parse_cpu_list(cpu_list_str)

            if len(actual_cpus) == expected_cpu_num:
                return True, stdout
        return False, stdout

    def determine_binding_strategy(self, cpu_num, numa_info):
        if cpu_num == 0:
            return 1, []

        if not numa_info:
            total_cpus, numa_nodes, cpu_info = self.get_numa_info()
            numa_info.update(cpu_info)

        max_single_numa = max(info['available_cpu_count'] for info in numa_info.values() if isinstance(info, dict))
        total_available_cpus = sum(info['available_cpu_count'] for info in numa_info.values() if isinstance(info, dict))

        if cpu_num > total_available_cpus:
            return 0, []

        if cpu_num > max_single_numa:
            needed_cpus = cpu_num
            binding_cpus = []
            for node, info in sorted(numa_info.items(), key=lambda x: x[1]['available_cpu_count'], reverse=True):
                if isinstance(info, dict):
                    if info['available_cpu_count'] >= needed_cpus:
                        binding_cpus.extend(info['available_cpus'][:needed_cpus])
                        return 2, binding_cpus
                    else:
                        binding_cpus.extend(info['available_cpus'])
                        needed_cpus -= info['available_cpu_count']
            return 2, binding_cpus

        for node, info in numa_info.items():
            if isinstance(info, dict) and info['available_cpu_count'] >= cpu_num:
                return 1, info['available_cpus'][:cpu_num]

        needed_cpus = cpu_num
        binding_cpus = []
        for node, info in sorted(numa_info.items(), key=lambda x: x[1]['available_cpu_count'], reverse=True):
            if isinstance(info, dict):
                if needed_cpus > 0:
                    take_cpus = min(needed_cpus, info['available_cpu_count'])
                    binding_cpus.extend(info['available_cpus'][:take_cpus])
                    needed_cpus -= take_cpus
                if needed_cpus == 0:
                    return 2, binding_cpus

        return 0, []

    def update_available_cpus(self, numa_data, cpu_info, bound_cpus):
        """Update available CPU info in numa_data."""
        for node, info in cpu_info.items():
            node_str = str(node)

            existing_available_cpus = set(numa_data[self.numa_info_key][node_str].get("available_cpus", []))

            available_cpus = existing_available_cpus - set(bound_cpus)
            numa_data[self.numa_info_key][node_str]["available_cpus"] = sorted(list(available_cpus))

            numa_data[self.numa_info_key][node_str]["available_cpu_count"] = len(
                numa_data[self.numa_info_key][node_str]["available_cpus"])

    def clean_up_json(self, numa_data, pod_info, hostname_pattern):
        """Clean non-existent Pod bindings and restore CPUs to numa_info."""
        matching_pods = [pod['pod_name'] for pod in pod_info if re.match(hostname_pattern, pod['pod_name'])]

        keys_to_delete = [key for key in numa_data.keys() if key not in matching_pods and key != self.numa_info_key]

        for key in keys_to_delete:
            pod_file_path = os.path.join(os.path.dirname(NUMA_INFO_PATH), key)

            bind_cpus = numa_data[key].get("bind_cpus", "")

            if bind_cpus and bind_cpus != "None":
                self.restore_cpus_to_numa_info(numa_data, bind_cpus)

            if not os.path.exists(pod_file_path):
                LOG.info(f"File {pod_file_path} does not exist. Removing entry from JSON: {key}")
                del numa_data[key]
            elif LockFile.is_locked(pod_file_path):
                LOG.info(f"Skipping removal of {key} because file {pod_file_path} is currently locked.")
            else:
                LOG.info(f"Removing outdated entry from JSON and deleting file: {key}")
                del numa_data[key]
                try:
                    os.remove(pod_file_path)
                except Exception as e:
                    LOG.error(f"Failed to delete file {pod_file_path}: {e}")

    @staticmethod
    def restore_cpus_to_numa_info(numa_data, bind_cpus):
        """Restore bound CPUs to numa_info."""
        cpu_list = CPUAllocator._parse_cpu_list(bind_cpus)

        for cpu in cpu_list:
            for node, info in numa_data["numa_info"].items():
                if info["min_cpu"] <= cpu <= info["max_cpu"]:
                    if cpu not in info["available_cpus"]:
                        info["available_cpus"].append(cpu)
                        info["available_cpus"].sort()
                    info["available_cpu_count"] = len(info["available_cpus"])
                    break

    def execute_binding(self, cpu_num, hostname, numa_data, cpu_info):
        """Execute CPU binding; skip if already bound."""
        if self.numa_info_key not in numa_data:
            numa_data[self.numa_info_key] = {}

        if hostname in numa_data:
            if numa_data[hostname].get("bind_flag", False):
                LOG.info(f"Host {hostname} is already bound successfully. Skipping binding.")
                return

        if not numa_data[self.numa_info_key]:
            total_cpus, numa_nodes, cpu_info = self.get_numa_info()
            numa_data[self.numa_info_key].update(cpu_info)

        binding_status, binding_cpus = self.determine_binding_strategy(cpu_num, numa_data[self.numa_info_key])

        if binding_status == 0:
            LOG.error("Binding failed: Insufficient CPUs.")
            numa_data[hostname] = {
                "bind_cpus": "",
                "bind_flag": False,
                "taskset_output": "Binding failed due to insufficient CPUs"
            }
        elif binding_status in (1, 2):
            if binding_status == 2:
                LOG.warning(f"Cross NUMA binding detected for host {hostname}. This may affect performance.")

            self.bind_cpu(binding_cpus)
            bind_successful, taskset_output = self.verify_binding(len(binding_cpus))

            if bind_successful:
                numa_data[hostname] = {
                    "bind_cpus": ",".join(map(str, binding_cpus)),
                    "bind_flag": True,
                    "taskset_output": taskset_output
                }
                self.update_available_cpus(numa_data, cpu_info, binding_cpus)
            else:
                LOG.error(f"NUMA binding failed for host {hostname}.")
                numa_data[hostname] = {
                    "bind_cpus": "",
                    "bind_flag": False,
                    "taskset_output": "Binding failed during verification"
                }

    def delete_binding_info(self, short_hostname):
        numa_data, file_handle = open_and_lock_json(NUMA_INFO_PATH)

        keys_to_delete = [key for key in numa_data.keys() if short_hostname in key]

        if keys_to_delete:
            for key in keys_to_delete:
                LOG.info(f"Deleting binding info for: {key}")

                bind_cpus = numa_data[key].get("bind_cpus")
                if bind_cpus and bind_cpus != "None":
                    self.restore_cpus_to_numa_info(numa_data, bind_cpus)

                pod_file_path = os.path.join(os.path.dirname(NUMA_INFO_PATH), key)
                if os.path.exists(pod_file_path):
                    try:
                        os.remove(pod_file_path)
                    except Exception as e:
                        LOG.error(f"Failed to delete file {pod_file_path}: {e}")

                del numa_data[key]

            write_and_unlock_json(numa_data, file_handle)
            LOG.info(f"NUMA information updated after deletion in {NUMA_INFO_PATH}")
        else:
            LOG.info(f"No matching entry found for hostname: {short_hostname}")


def format_cpu_ranges(cpu_list):
    """Format CPU list as ranges (e.g. 0-31,64-95)."""
    if not cpu_list:
        return ""

    cpu_list = sorted(set(map(int, cpu_list)))
    ranges = []
    range_start = cpu_list[0]
    range_end = cpu_list[0]

    for i in range(1, len(cpu_list)):
        if cpu_list[i] == range_end + 1:
            range_end = cpu_list[i]
        else:
            if range_start == range_end:
                ranges.append(str(range_start))
            else:
                ranges.append(f"{range_start}-{range_end}")
            range_start = cpu_list[i]
            range_end = cpu_list[i]

    if range_start == range_end:
        ranges.append(str(range_start))
    else:
        ranges.append(f"{range_start}-{range_end}")

    return ",".join(ranges)


def show_numa_binding_info(numa_info_path):
    """Query and display NUMA binding info for each Pod from numa-pod.json."""
    try:
        numa_data, file_handle = open_and_lock_json(numa_info_path)
    except Exception as err:
        LOG.error(f"Error loading NUMA info from {numa_info_path}: {err}")
        return

    col1_width = 40
    col2_width = 20

    print(f"{'Pod Name'.ljust(col1_width)} {'Bind CPUs'.ljust(col2_width)}")

    for pod_name, pod_info in numa_data.items():
        if pod_name == "numa_info":
            continue

        bind_cpus = pod_info.get("bind_cpus", "")

        if bind_cpus:
            try:
                cpu_list = list(map(int, bind_cpus.split(','))) if bind_cpus else []
                formatted_cpus = format_cpu_ranges(cpu_list)
            except ValueError:
                formatted_cpus = bind_cpus
        else:
            formatted_cpus = ""

        print(f"{pod_name.ljust(col1_width)} {formatted_cpus.ljust(col2_width)}")

    try:
        cmd = "lscpu | grep -i 'NUMA node[0-9] CPU(s)'"
        return_code, stdout, stderr = exec_popen(cmd, timeout=TIME_OUT)
        if return_code:
            LOG.error(f"Error retrieving NUMA info: {stderr}")
            return

        print("\nNUMA:")
        for line in stdout.splitlines():
            print(line)

    except Exception as e:
        LOG.error(f"Error fetching NUMA CPU distribution: {e}")


def main():
    cpu_allocator = CPUAllocator()
    cpu_num = cpu_allocator.get_cpu_num()
    short_hostname = cpu_allocator.get_hostname()

    kube_config_path = _paths.kube_config
    k8s_service = KubernetesService(kube_config_path)

    try:
        all_pod_info = k8s_service.get_all_pod_info()
        if not all_pod_info:
            err_msg = "No Pods found in the cluster."
            LOG.error(err_msg)
            raise Exception(err_msg)
    except Exception as e:
        err_msg = f"Error fetching pod information: {e}"
        LOG.error(err_msg)
        raise Exception(err_msg)

    try:
        total_cpus, numa_nodes, cpu_info = cpu_allocator.get_numa_info()
    except Exception as e:
        err_msg = f"Error fetching NUMA info: {e}"
        LOG.error(err_msg)
        raise Exception(err_msg)

    numa_data, file_handle = open_and_lock_json(NUMA_INFO_PATH)

    try:
        start_time = time.time()
        while True:
            try:
                pod_name_full = get_pod_name_from_info(all_pod_info, short_hostname)
                if pod_name_full:
                    hostname_pattern = r'ograc.*-node.*'
                    cpu_allocator.clean_up_json(numa_data, all_pod_info, hostname_pattern)

                    cpu_allocator.execute_binding(cpu_num, pod_name_full, numa_data, cpu_info)
                    pod_file_path = os.path.join(os.path.dirname(NUMA_INFO_PATH), pod_name_full)
                    break
            except Exception as e:
                err_msg = f"Error during CPU binding: {e}"
                LOG.error(err_msg)
                raise Exception(err_msg)

            if time.time() - start_time >= MAX_CHECK_TIME:
                err_msg = "Pod not found in the cluster."
                LOG.error(err_msg)
                raise Exception("Pod not found in the cluster.")
            else:
                all_pod_info = k8s_service.get_all_pod_info()
                time.sleep(CHECK_INTERVAL)

    finally:
        write_and_unlock_json(numa_data, file_handle)

    LOG.info("NUMA information updated successfully.")

    return pod_file_path


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "show":
        show_numa_binding_info(NUMA_INFO_PATH)
    else:
        pod_file_path = main()
        print(pod_file_path)
