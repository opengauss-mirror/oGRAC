#!/usr/bin/env python3

import ast
import atexit
import os
import re
import stat
import base64
import tempfile

import requests
import urllib3

# 禁用 InsecureRequestWarning 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _read_kubeconfig_value(config_content, key):
    pattern = r"^\s*{}\s*:\s*(.*?)\s*$".format(re.escape(key))
    match = re.search(pattern, config_content, re.MULTILINE)
    if not match:
        return None

    value = match.group(1).strip()
    if value.startswith(("'", '"')):
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            try:
                return ast.literal_eval(value.split(" #", 1)[0].rstrip())
            except (SyntaxError, ValueError) as error:
                raise ValueError("invalid {} value in kubeconfig".format(key)) from error
    return value.split(" #", 1)[0].rstrip()


def _decode_config_data(value, field_name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("{} must be a non-empty string".format(field_name))
    try:
        encoded_value = re.sub(r"\s+", "", value.strip())
        return base64.b64decode(encoded_value, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("{} is not valid base64 data".format(field_name)) from error


def _write_private_file(path, data):
    file_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                      stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(file_fd, "wb") as output_file:
        output_file.write(data)


class KubernetesService:
    def __init__(self, kube_config_path):
        self.kube_config_path = kube_config_path
        self.api_server = "https://kubernetes.default.svc"
        self.cert = None
        self.verify = True
        self._cert_dir = None
        self.headers = {"Accept": "application/json"}
        atexit.register(self.close)
        try:
            self._load_kube_config()
        except Exception:
            self.close()
            raise

    def close(self):
        if self._cert_dir is not None:
            self._cert_dir.cleanup()
            self._cert_dir = None
        self.cert = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _load_kube_config(self):
        with open(self.kube_config_path, "r") as kube_config_file:
            kube_config_content = kube_config_file.read()

        client_cert_data = _decode_config_data(
            _read_kubeconfig_value(kube_config_content, "client-certificate-data"),
            "client-certificate-data")
        client_key_data = _decode_config_data(
            _read_kubeconfig_value(kube_config_content, "client-key-data"),
            "client-key-data")

        self._cert_dir = tempfile.TemporaryDirectory(prefix="ograc-kube-")
        cert_dir = self._cert_dir.name
        os.chmod(cert_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        cert_file_path = os.path.join(cert_dir, "client-cert.pem")
        key_file_path = os.path.join(cert_dir, "client-key.pem")
        _write_private_file(cert_file_path, client_cert_data)
        _write_private_file(key_file_path, client_key_data)
        self.cert = (cert_file_path, key_file_path)

        ca_data = _read_kubeconfig_value(kube_config_content, "certificate-authority-data")
        ca_path = _read_kubeconfig_value(kube_config_content, "certificate-authority")
        if ca_data is not None:
            ca_file_path = os.path.join(cert_dir, "ca.pem")
            _write_private_file(ca_file_path, _decode_config_data(
                ca_data, "certificate-authority-data"))
            self.verify = ca_file_path
        elif ca_path is not None:
            if not isinstance(ca_path, str) or not ca_path.strip():
                raise ValueError("certificate-authority must be a non-empty path")
            ca_path = os.path.expandvars(os.path.expanduser(ca_path.strip()))
            if not os.path.isabs(ca_path):
                ca_path = os.path.join(os.path.dirname(os.path.abspath(self.kube_config_path)), ca_path)
            ca_path = os.path.abspath(ca_path)
            if not os.path.isfile(ca_path) or not os.access(ca_path, os.R_OK):
                raise FileNotFoundError("certificate-authority file is missing or unreadable: {}".format(ca_path))
            self.verify = ca_path

    def _get(self, path, timeout=5):
        url = f"{self.api_server}{path}"
        response = requests.get(url, headers=self.headers, cert=self.cert, verify=self.verify, timeout=timeout)
        response.raise_for_status()
        return response.json()

    def get_service_by_pod_name(self, pod_name, timeout=5):
        services_data = self._get("/api/v1/services", timeout=timeout)
        pods_data = self._get("/api/v1/pods", timeout=timeout)

        try:
            for service in services_data.get("items", []):
                service_selector = service["spec"].get("selector", {})
                if not service_selector:
                    continue

                matching_pods = []
                for pod in pods_data.get("items", []):
                    pod_labels = pod["metadata"].get("labels", {})
                    if all(item in pod_labels.items() for item in service_selector.items()):
                        matching_pods.append(pod)

                for pod in matching_pods:
                    if pod_name in pod.get("metadata", {}).get("name", ""):
                        return service["metadata"]["name"]
        except Exception as e:
            print(f"Error getting service by pod name: {e}")
            return None

    def get_pod_info_by_service(self, service_name):
        services_data = self._get("/api/v1/services")
        pods_data = self._get("/api/v1/pods")
        target_service = None

        for service in services_data.get("items", []):
            if service["metadata"]["name"] == service_name:
                target_service = service
                break

        if not target_service:
            return []

        service_selector = target_service["spec"].get("selector", {})
        matching_pods = []
        for pod in pods_data.get("items", []):
            pod_labels = pod["metadata"].get("labels", {})
            if all(item in pod_labels.items() for item in service_selector.items()):
                matching_pods.append(pod)

        pod_info = []
        for pod in matching_pods:
            pod_name = pod.get("metadata", {}).get("name")
            pod_ip = pod.get("status", {}).get("podIP")
            containers = pod.get("spec", {}).get("containers", [])
            for container in containers:
                ports = container.get("ports", [])
                for port in ports:
                    container_port = port.get("containerPort")
                    if pod_name and pod_ip and container_port:
                        pod_info.append({
                            "pod_name": pod_name,
                            "pod_ip": pod_ip,
                            "container_port": container_port
                        })

        return pod_info

    def get_all_pod_info(self, timeout=5):
        services_data = self._get("/api/v1/services", timeout=timeout)
        pods_data = self._get("/api/v1/pods", timeout=timeout)

        all_pod_info = []

        for service in services_data.get("items", []):
            service_selector = service["spec"].get("selector", {})
            if not service_selector:
                continue

            matching_pods = []
            for pod in pods_data.get("items", []):
                pod_labels = pod["metadata"].get("labels", {})
                if all(item in pod_labels.items() for item in service_selector.items()):
                    matching_pods.append(pod)

            for pod in matching_pods:
                pod_name_all = pod.get("metadata", {}).get("name")
                pod_ip = pod.get("status", {}).get("podIP")
                containers = pod.get("spec", {}).get("containers", [])
                for container in containers:
                    ports = container.get("ports", [])
                    for port in ports:
                        container_port = port.get("containerPort")
                        if pod_name_all and pod_ip and container_port:
                            all_pod_info.append({
                                "service_name": service["metadata"]["name"],
                                "pod_name": pod_name_all,
                                "pod_ip": pod_ip,
                                "container_port": container_port
                            })

        return all_pod_info

    def get_pods(self):
        return self._get("/api/v1/pods")

    def delete_pod(self, name, namespace, timeout=5):
        url = f"{self.api_server}/api/v1/namespaces/{namespace}/pods/{name}"
        response = requests.delete(url, headers=self.headers, cert=self.cert, verify=self.verify, timeout=timeout)
        response.raise_for_status()
        return response.json()

    def get_pod_by_name(self, pod_name):
        pods_data = self.get_pods()

        try:
            for pod in pods_data.get("items", []):
                if pod_name == pod["metadata"]["name"]:
                    return pod
        except Exception as e:
            print(f"Error getting pod by name: {e}")
            return None
