#!/usr/bin/env python3
import os
import shlex
import subprocess
import json
import sys
from pathlib import Path

_CUR_DIR = os.path.dirname(os.path.abspath(__file__))
_INSPECTION_DIR = os.path.abspath(os.path.join(_CUR_DIR, "../.."))
sys.path.insert(0, _INSPECTION_DIR)

from config import get_config

_cfg = get_config()
_paths = _cfg.paths


class OmChecker:

    def __init__(self):
        self.decode_mod = 'utf-8'
        self.component_check_order = ['cms', 'ograc', 'ograc_exporter']
        self.check_file_parent_path = _paths.action_dir
        self.check_file = 'check_status.sh'
        self.check_daemon_cmd = f'pgrep -f "{_paths.ograc_daemon_script}"'
        self.check_timer_cmd = f'systemctl is-active {_paths.daemon_timer_unit}'
        self.check_res_flag = True
        self.check_note = {
            'cms': 'unknown',
            'ograc': 'unknown',
            'og_om': 'unknown',
            'ograc_exporter': 'unknown',
            'ograc_daemon': 'unknown',
            'ograc_timer': 'unknown'
        }
        self.format_output = {
            'data': {},
            'error': {
                'code': 0,
                'description': ''
            }
        }

    def check_ctom(self):
        key_file = 'ogmgr/uds_server.py'
        check_popen = subprocess.Popen(['/usr/bin/pgrep', '-f', key_file],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        og_om_pid, _ = check_popen.communicate(timeout=60)
        if og_om_pid.decode(self.decode_mod):
            self.check_note['og_om'] = 'online'
        else:
            self.check_note['og_om'] = 'offline'
            self.check_res_flag = False

    def check_components(self):
        for component in self.component_check_order:
            script_path = str(Path(os.path.join(self.check_file_parent_path, component, self.check_file)))
            check_popen = subprocess.Popen(['/usr/bin/bash', script_path],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            _, err = check_popen.communicate(timeout=60)
            if err.decode(self.decode_mod):
                continue

            check_result = check_popen.returncode
            if check_result:
                self.check_note[component] = 'offline'
                self.check_res_flag = False
            else:
                self.check_note[component] = 'online'

    def check_daemon(self):
        daemon = subprocess.Popen(shlex.split(self.check_daemon_cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  shell=False)
        output, err = daemon.communicate(timeout=60)
        if not err.decode(self.decode_mod):
            if output.decode(self.decode_mod):
                self.check_note['ograc_daemon'] = 'online'
            else:
                self.check_note['ograc_daemon'] = 'offline'
                self.check_res_flag = False

    def check_ograc_timer(self):
        daemon = subprocess.Popen(shlex.split(self.check_timer_cmd), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, shell=False)
        output, err = daemon.communicate(timeout=60)
        if not err.decode(self.decode_mod):
            if output.decode(self.decode_mod).strip() == 'active':
                self.check_note['ograc_timer'] = 'active'

            if output.decode(self.decode_mod).strip() == 'inactive':
                self.check_note['ograc_timer'] = 'inactive'
                self.check_res_flag = False

    def get_format_output(self):
        try:
            self.check_components()
        except Exception as err:
            self.format_output['error']['code'] = 1
            self.format_output['error']['description'] = "check components failed with err: {}".format(str(err))
            return self.format_output

        try:
            self.check_ctom()
        except Exception as err:
            self.format_output['error']['code'] = 1
            self.format_output['error']['description'] = "check og_om status failed with err: {}".format(str(err))
            return self.format_output

        try:
            self.check_daemon()
        except Exception as err:
            self.format_output['error']['code'] = 1
            self.format_output['error']['description'] = "check ograc_daemon failed with err: {}".format(str(err))
            return self.format_output

        try:
            self.check_ograc_timer()
        except Exception as err:
            self.format_output['error']['code'] = 1
            self.format_output['error']['description'] = "check ograc timer fained with err: {}".format(str(err))
            return self.format_output
        if not self.check_res_flag:
            self.format_output['error']['code'] = 1
            self.format_output['error']['description'] = "check ograc status failed, details: %s" % self.check_note
        self.format_output['data'] = self.check_note
        return self.format_output


if __name__ == '__main__':
    oc = OmChecker()
    print(json.dumps(oc.get_format_output()))
