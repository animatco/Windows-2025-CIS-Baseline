# frozen_string_literal: true

## Auto-generated from ansible-lockdown/Windows-2025-CIS Ansible role
## Source section: section01_cloud_lockout_order


control 'cis-1.2.2' do
  impact 1.0
  title 'Ensure Account lockout threshold is set to 5 or fewer invalid logon attempt(s), but not 0.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.2.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '1.2.2'
  pol = local_security_policy
  only_if('Local Security Policy not readable via secedit on this target') { pol.available? }

  describe local_security_policy do
    its('LockoutBadCount') { should cmp 5 }
  end
end

control 'cis-1.2.1' do
  impact 1.0
  title 'Ensure Account lockout duration is set to 15 or more minutes'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.2.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '1.2.1'
  pol = local_security_policy
  only_if('Local Security Policy not readable via secedit on this target') { pol.available? }

  describe local_security_policy do
    its('LockoutDuration') { should cmp 15 }
  end
end

control 'cis-1.2.3' do
  impact 1.0
  title 'Ensure Allow Administrator account lockout is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.2.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '1.2.3'
  pol = local_security_policy
  only_if('Local Security Policy not readable via secedit on this target') { pol.available? }

  describe local_security_policy do
    its('AllowAdministratorLockout') { should cmp 1 }
  end
end

control 'cis-1.2.4' do
  impact 1.0
  title 'Ensure Reset account lockout counter after is set to 15 or more minutes.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.2.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '1.2.4'
  pol = local_security_policy
  only_if('Local Security Policy not readable via secedit on this target') { pol.available? }

  describe local_security_policy do
    its('ResetLockoutCount') { should cmp 15 }
  end
end