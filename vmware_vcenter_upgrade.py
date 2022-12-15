#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Dustin Scott <dustin.scott18@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vmware_vcenter_upgrade
short_description: Upgrade a vCenter appliance
description:
- This module can be used to upgrade a vCenter appliance.
author:
- Dustin Scott (@scottd018) <dustin.scott18@gmail.com>
notes:
- Tested on vSphere 7.0u3
requirements:
- requests
options:
  version:
    description:
    - Upgrade to a specific version.
    required: False
    type: str
    default: latest
  ignore_warnings:
    description:
    - Ignore precheck warnings.
    required: False
    type: bool
    default: False
  action:
    description:
    - "upgrade: Upgrade to a specified version as indicated by C(version)."
    - "stage: Only stage the upgrade as indicated by C(version)."
    - "query: Do not perform upgrade but simply list upgrades."
    default: upgrade
    choices: [ upgrade, stage, query ]
    type: str
extends_documentation_fragment:
- community.vmware.vmware.documentation
'''

EXAMPLES = r'''
- name: upgrade vmware vcenter to latest version
  vmware_vcenter_upgrade:
      hostname: '{{ vcenter_hostname }}'
      username: '{{ vcenter_username }}'
      password: '{{ vcenter_password }}'
      action:   'upgrade'
  delegate_to: localhost

- name: upgrade vmware vcenter to specific version
  vmware_vcenter_upgrade:
      hostname: '{{ vcenter_hostname }}'
      username: '{{ vcenter_username }}'
      password: '{{ vcenter_password }}'
      action:   'upgrade'
      version:  '7.0.3.00100'
  delegate_to: localhost

- name: stage vmware vcenter specific version upgrade
  vmware_vcenter_upgrade:
      hostname: '{{ vcenter_hostname }}'
      username: '{{ vcenter_username }}'
      password: '{{ vcenter_password }}'
      action:   'stage'
      version:  '7.0.3.00100'
  delegate_to: localhost

- name: list vmware vcenter upgrade information
  vmware_vcenter_upgrade:
      hostname: '{{ vcenter_hostname }}'
      username: '{{ vcenter_username }}'
      password: '{{ vcenter_password }}'
      action:   'query'
  delegate_to: localhost
'''

RETURN = r'''
'''

try:
    import requests
    import time
    from packaging import version
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.vmware.plugins.module_utils.vmware import PyVmomi, option_diff, vmware_argument_spec
from ansible.module_utils._text import to_native


class VMwareVCenterUpgrade(PyVmomi):
    def __init__(self, module):
        super(VMwareVCenterUpgrade, self).__init__(module)

        self.username = module.params['username']
        self.password = module.params['password']
        self.validate_certs = module.params['validate_certs']

        self.version = module.params['version']
        self.action = module.params['action']
        self.ignore_warnings = module.params['ignore_warnings']

        self.base_url = self.get_base_url(module)
        self.auth_url = '%s/rest/com/vmware/cis/session' % self.base_url
        self.upgrade_url = '%s/rest/appliance/update/pending' % self.base_url
        self.version_url = None
        self.auth_header = None
        self.upgrade_data = None
        self.upgrade_version = None

    def process_action(self):
        upgrade_actions = {
            'upgrade': {
                'is_latest': self.state_exit_unchanged,
                'needs_action': self.upgrade,
            },
            'stage': {
                'is_latest': self.state_exit_unchanged,
                'needs_action': self.stage,
            },
            'query': {
                'query': self.state_exit_unchanged,
            },
        }
        try:
            upgrade_actions[self.action][self.check_upgrade_state()]()
        except Exception as e:
            self.module.fail_json(msg=to_native(e))

    def state_exit_unchanged(self):
        self.module.exit_json(changed=False,upgrade_data=self.upgrade_data)

    def get_auth_token(self):
        token_response = requests.post(
            self.auth_url,
            auth=(self.username, self.password),
            verify=self.validate_certs,
        )

        if not (token_response.status_code is 200 or token_response.status_code is 201):
            self.module.fail_json(
                msg='Unable to authenticate with vCenter server REST API: %s' % token_response.json(),
            )

        # set the auth info
        self.auth_header = {
            'vmware-api-session-id': token_response.json()['value'],
        }

    def get_base_url(self, module):
        server_base = 'https://%s' % module.params['hostname']

        if module.params['port']:
            server_base = '%s:%s' % (server_base,module.params['port'])

        return server_base

    def get_upgrades(self):
        self.get_auth_token()

        upgrade_response = self.call_rest(self.upgrade_url + '?source_type=LOCAL_AND_ONLINE', 'get')

        self.upgrade_data = upgrade_response.json()['value']

    def get_upgrade_from_version(self):
        for upgrade_version in self.upgrade_data:
            if upgrade_version['version'] is self.version:
                
        return self.version

    def get_upgrade_from_latest(self):
        latest = '0.0.0'

        for upgrade_version in self.upgrade_data:
            if version.parse(upgrade_version['version']) > version.parse(latest):
                latest = upgrade_version['version']

        return latest

    def get_upgrade_version(self):
        if not self.version == 'latest':
            self.upgrade_version = self.get_upgrade_from_version()
        else:
            self.upgrade_version = self.get_upgrade_from_latest()

        if self.upgrade_version == '0.0.0':
            self.module.fail_json(
                msg='Unable to find vCenter upgrade version: %s' % self.version,
            )

        self.version_url = '%s/%s' % (self.upgrade_url, self.upgrade_version)

    def call_rest(self, url, action, body=None, fail_on_error=True):
        response = None
        default_args = {
            'headers': self.auth_header,
            'verify': self.validate_certs,
        }

        if body:
            default_args['json'] = body

        if action == 'get':
            response = requests.get(url, **default_args)
        elif action == 'post':
            response = requests.post(url, **default_args)
        else:
            self.module.fail_json(
                msg='Internal error in call_rest method; action %s is invalid for this module' % action,
            )

        if fail_on_error:
            if not (response.status_code is 200 or response.status_code is 201):
                self.module.fail_json(
                    msg='Error in call_rest method: %s' % response.json(),
                )

        return response

    def check_upgrade_state(self):
        self.get_upgrades()

        # determine if action is needed or if the system is in its desired state
        if self.action == 'query':
            return 'query'
        elif self.action == 'stage':
            self.get_upgrade_version()

            if self.is_staged():
                return 'is_latest'
        elif self.action == 'upgrade':
            self.get_upgrade_version()

            if len(self.upgrade_data) == 0:
                return 'is_latest'

        return 'needs_action'

    def precheck(self):
        precheck_response = self.call_rest(self.version_url + '?action=precheck', 'post')

        if len(precheck_response.json()['value']['issues']['errors']) > 0:
            self.module.fail_json(
                msg='Failed vCenter upgrade precheck: %s' % precheck_response.json()['value']['issues']['errors'],
            )

        if not self.ignore_warnings:
            if len(precheck_response.json()['value']['issues']['warnings']) > 0:
                self.module.fail_json(
                    msg='Failed vCenter upgrade precheck: %s' % precheck_response.json()['value']['issues']['warnings'],
                )

    def validate(self, user_data):
        validate_response = self.call_rest(self.version_url + '?action=validate', 'post', body=user_data)

        if len(validate_response.json()['value']['errors']) > 0:
            self.module.fail_json(
                msg='Failed vCenter upgrade validation: %s' % validate_response.json()['value']['errors'],
            )

        if not self.ignore_warnings:
            if len(validate_response.json()['value']['warnings']) > 0:
                self.module.fail_json(
                    msg='Failed vCenter upgrade validation: %s' % validate_response.json()['value']['warnings'],
                )

    def is_staged(self):
        is_staged_url = '%s/rest/appliance/update/staged' % self.base_url
        is_staged_response = self.call_rest(is_staged_url, 'get', fail_on_error=False)

        if not (is_staged_response.status_code is 200 or is_staged_response.status_code is 201):
            for msg in is_staged_response.json()['value']['messages']:
                if msg['id'] == 'com.vmware.applmgmt.update.no_stage':
                    return False

            self.module.fail_json(
                msg='Unable to check vCenter upgrade staging status: %s' % is_staged_response.json(),
            )

        return is_staged_response.json()['value']['staging_complete']

    def stage(self, exit=True):
        self.precheck()

        # TODO: try/catch with helpful errors
        stage_response = self.call_rest(self.version_url + '?action=stage', 'post')

        # TODO: this needs a timeout
        finished_staging = False
        while not finished_staging:
            finished_staging = self.is_staged()
            time.sleep(5)

        if exit:
            self.module.exit_json(changed=True,upgrade_data=self.upgrade_data)

    def upgrade(self):
        # ensure installation media is staged
        if not self.is_staged():
            self.stage(exit=False)

        user_data_body = {
            "user_data": {
                "key": self.username
            }
        }

        # validate the pending installation
        self.validate(user_data_body)

        # run the installation
        self.call_rest(self.version_url + '?action=install', 'post', body=user_data_body)

        self.module.exit_json(changed=True,upgrade_data=self.upgrade_data)


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(
        version=dict(type='str', default='latest'),
        ignore_warnings=dict(type='bool', default=False),
        action=dict(type='str', default='upgrade', choices=['upgrade', 'stage', 'query'])
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
    )

    vmware_vcenter_upgrade = VMwareVCenterUpgrade(module)
    vmware_vcenter_upgrade.process_action()


if __name__ == '__main__':
    main()
