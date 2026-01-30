# frozen_string_literal: true

## Auto-generated from ansible-lockdown/Windows-2025-CIS Ansible role
## Source section: section05
only_if('Section 05 disabled by input') { input('run_section_05') }

control 'cis-5.1' do
  impact 1.0
  title 'Ensure Print Spooler (Spooler) is set to Disabled Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 5.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '5.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Spooler') do
    its('Start') { should cmp 4 }
  end
end

control 'cis-5.2' do
  impact 1.0
  title 'Ensure Print Spooler (Spooler) is set to Disabled Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 5.2.'
  only_if('Level 2 controls disabled') { input('run_level_2') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '5.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Spooler') do
    its('Start') { should cmp 4 }
  end
end
