# Description

This is a custom Ansible module which allows you to upgrade a VMware vCenter
Server appliance.

**NOTE:** tested on VCSA 7.0u3

# Pip requirements

- requests
- pyvmomi

All pip requirements are in the requirements.txt file, you can install them with this command: 
```
pip install -r requirements.txt
```
# Installation

- Move the python module wherever you'd like (e.g. /path/to/ansible/modules)
- Ensure the path where you've placed the module is in the Ansible library path
  either via the config or other mechanism, for example:

```
[defaults]
library = ~/.ansible/plugins/modules:/usr/share/ansible/plugins/modules:/path/to/ansible/modules
```

# Usage

Once installed above, your documentation is available with examples:

```
ansible-doc vmware_vcenter_upgrade
```

# Examples (from Docs)

```yaml
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
```
