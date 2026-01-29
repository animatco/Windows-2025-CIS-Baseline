# Windows Server 2025 CIS InSpec Baseline Profile

## Overview
This repository contains an **InSpec compliance baseline** generated from the official Ansible Lockdown role for **CIS Windows Server 2025**. The profile validates system configuration against CIS recommendations using read-only checks suitable for audit, compliance, and continuous validation pipelines.

This profile supports:
- CIS Level 1 and Level 2 controls
- Member Server and Domain Controller roles
- Inputs-based toggling for flexible execution

The baseline is designed for use with Chef InSpec, CI/CD pipelines, and enterprise compliance tooling.

---

## Key Features

- 1:1 validation coverage for registry, services, Windows features, firewall, and audit policy controls
- Local Security Policy and User Rights validation via exported policy parsing
- CIS control ID alignment for audit traceability
- Inputs to toggle CIS levels and server role
- Gap report for items that require manual or custom validation

---

## Repository Structure

```
windows-2025-cis-inspec/
  inspec.yml
  README.md
  inputs.yml

  controls/
    cis-1-account-policies.rb
    cis-2-local-policies.rb
    cis-9-firewall.rb
    cis-17-advanced-audit.rb
    cis-18-admin-templates.rb
    cis-services.rb
    cis-features.rb

  libraries/
    local_security_policy.rb
    user_right.rb
    auditpol_helper.rb

  GAP_REPORT.md
```

---

## Inputs

This profile uses InSpec inputs to control execution scope.

### CIS Level Toggles

| Input Name     | Type    | Default | Description                    |
|----------------|---------|---------|--------------------------------|
| `run_level_1` | Boolean | true    | Enable CIS Level 1 controls    |
| `run_level_2` | Boolean | false   | Enable CIS Level 2 controls    |

### Server Role

| Input Name    | Type   | Default         | Allowed Values                     |
|---------------|--------|-----------------|------------------------------------|
| `server_role`| String | member_server  | `member_server`, `domain_controller` |

These inputs are defined in `inputs.yml` and can be overridden at runtime.

---

## Running the Profile

### Member Server — CIS Level 1 Only

```powershell
inspec exec . -t winrm://SERVER \
  --input run_level_1=true \
  --input run_level_2=false \
  --input server_role=member_server
```

### Domain Controller — CIS Level 2 Only

```powershell
inspec exec . -t winrm://DC01 \
  --input run_level_1=false \
  --input run_level_2=true \
  --input server_role=domain_controller
```

### Both Levels (Not Typical, But Supported)

```powershell
inspec exec . -t winrm://SERVER \
  --input run_level_1=true \
  --input run_level_2=true
```

---

## Control Logic

Controls are conditionally executed using input guards, for example:

- Only run Level 1 controls when `run_level_1 == true`
- Only run Level 2 controls when `run_level_2 == true`
- Only run Domain Controller controls when `server_role == 'domain_controller'`

This allows a single profile to be reused across heterogeneous Windows Server estates.

---

## Local Security Policy & User Rights

Some CIS controls require validation of Local Security Policy and User Rights Assignments.

This profile includes custom InSpec libraries that:

1. Export local security policy using `secedit`
2. Parse the exported configuration
3. Validate account policies, security options, and user rights assignments

These helpers are located in:

```
libraries/local_security_policy.rb
libraries/user_right.rb
```

---

## Advanced Audit Policy

Advanced Audit Policy (CIS Section 17) is validated using `auditpol` output parsing via:

```
libraries/auditpol_helper.rb
```

This ensures parity with how Ansible Lockdown configures subcategories.

---

## GAP_REPORT.md

`GAP_REPORT.md` documents CIS items that could not be automatically translated, typically including:

- Procedural remediation tasks
- Settings applied via complex shell logic
- Items requiring domain GPO context

These gaps are intentional and should be reviewed for:

- Manual validation
- Domain GPO compliance checks
- Custom InSpec control development

---

## Compliance & Audit Use

This baseline is suitable for:

- Internal audit validation
- Continuous compliance in CI/CD pipelines
- Integration with compliance tooling (e.g., Chef Automate, reporting systems)
- Evidence generation for CIS, SOX, HIPAA, and other regulatory frameworks

---

## Source & Traceability

This profile was generated from:

- Ansible Lockdown: Windows-2025-CIS role

All controls retain CIS-aligned structure and identifiers to support traceability between:

- CIS Benchmark
- Ansible remediation
- InSpec validation

---

## Recommended Enhancements

Optional improvements for enterprise environments:

- Map `impact` values based on Level 1 vs Level 2
- Split DC/MS profiles for stricter separation
- Add domain GPO validation controls
- Integrate with Remedio/Tanium evidence workflows

---

## Maintainer

Steve Gold  


---

## Disclaimer

This InSpec profile performs validation only. It does not remediate system configuration. Use Ansible Lockdown or approved configuration management tooling for enforcement.

