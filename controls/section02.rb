# frozen_string_literal: true

## Auto-generated from ansible-lockdown/Windows-2025-CIS Ansible role
## Source section: section02

control 'cis-2.2.1' do
  impact 1.0
  title 'Ensure Access Credential Manager as a trusted caller is set to No One'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.1'
  describe user_right('SeTrustedCredManAccessPrivilege') do
    it { should eq [] }
  end
end

control 'cis-2.2.2' do
  impact 1.0
  title 'Ensure Access this computer from the network is set to Administrators, Authenticated Users, & ENTERPRISE DOMAIN CONTROLLERS DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.2.2'
  describe user_right('SeNetworkLogonRight') do
    it { should include 'Administrators' }
    it { should include 'Authenticated Users' }
    it { should include 'ENTERPRISE DOMAIN CONTROLLERS' }
  end
end

control 'cis-2.2.3' do
  impact 1.0
  title 'Ensure Access this computer from the network is set to Administrators, Authenticated Users, & ENTERPRISE DOMAIN CONTROLLERS MS only | Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.2.3'
  describe user_right('SeNetworkLogonRight') do
    it { should include 'Administrators' }
    it { should include 'Authenticated Users' }
  end
end

control 'cis-2.2.4' do
  impact 1.0
  title 'Ensure Act as part of the operating system is set to No One'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.4'
  describe user_right('SeTcbPrivilege') do
    it { should eq [] }
  end
end

control 'cis-2.2.5' do
  impact 1.0
  title 'Ensure Add workstations to domain is set to Administrators DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.5.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.2.5'
  describe user_right('SeMachineAccountPrivilege') do
    it { should include 'A' }
    it { should include 'd' }
    it { should include 'm' }
    it { should include 'i' }
    it { should include 'n' }
    it { should include 'i' }
    it { should include 's' }
    it { should include 't' }
    it { should include 'r' }
    it { should include 'a' }
    it { should include 't' }
    it { should include 'o' }
    it { should include 'r' }
    it { should include 's' }
  end
end

control 'cis-2.2.6' do
  impact 1.0
  title 'Ensure Adjust memory quotas for a process is set to Administrators LOCAL SERVICE NETWORK SERVICE'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.6.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.6'
  describe user_right('SeIncreaseQuotaPrivilege') do
    it { should include 'Administrators' }
    it { should include 'LOCAL SERVICE' }
    it { should include 'NETWORK SERVICE' }
  end
end

control 'cis-2.2.7' do
  impact 1.0
  title 'Ensure Allow log on locally is set to Administrators, ENTERPRISE DOMAIN CONTROLLERS (DC only)'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.7.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.2.7'
  describe user_right('SeInteractiveLogonRight') do
    it { should include 'Administrators' }
    it { should include 'ENTERPRISE DOMAIN CONTROLLERS' }
  end
end

control 'cis-2.2.8' do
  impact 1.0
  title 'Ensure Allow log on locally is set to Administrators (MS only)'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.8.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.2.8'
  describe user_right('SeInteractiveLogonRight') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.9' do
  impact 1.0
  title "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DC only)"
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.9.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.2.9'
  describe user_right('SeRemoteInteractiveLogonRight') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.10' do
  impact 1.0
  title "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (MS Only)"
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.10.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.2.10'
  describe user_right('SeRemoteInteractiveLogonRight') do
    it { should include 'Administrators' }
    it { should include 'Remote Desktop Users' }
  end
end

control 'cis-2.2.11' do
  impact 1.0
  title 'Ensure Back up files and directories is set to Administrators'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.11.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.11'
  describe user_right('SeBackupPrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.12' do
  impact 1.0
  title 'Ensure Change the system time is set to Administrators LOCAL SERVICE'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.12.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.12'
  describe user_right('SeSystemTimePrivilege') do
    it { should include 'Administrators' }
    it { should include 'LOCAL SERVICE' }
  end
end

control 'cis-2.2.13' do
  impact 1.0
  title 'Ensure Change the time zone is set to Administrators LOCAL SERVICE'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.13.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.13'
  describe user_right('SeTimeZonePrivilege') do
    it { should include 'Administrators' }
    it { should include 'LOCAL SERVICE' }
  end
end

control 'cis-2.2.14' do
  impact 1.0
  title 'Ensure Create a pagefile is set to Administrators'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.14.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.14'
  describe user_right('SeCreatePagefilePrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.15' do
  impact 1.0
  title 'Ensure Create a token object is set to No One'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.15.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.15'
  describe user_right('SeCreateTokenPrivilege') do
    it { should eq [] }
  end
end

control 'cis-2.2.16' do
  impact 1.0
  title 'Ensure Create global objects is set to Administrators LOCAL SERVICE NETWORK SERVICE SERVICE'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.16.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.16'
  describe user_right('SeCreateGlobalPrivilege') do
    it { should include 'Administrators' }
    it { should include 'LOCAL SERVICE' }
    it { should include 'NETWORK SERVICE' }
    it { should include 'SERVICE' }
  end
end

control 'cis-2.2.17' do
  impact 1.0
  title 'Ensure Create permanent shared objects is set to No One'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.17.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.17'
  describe user_right('SeCreatePermanentPrivilege') do
    it { should eq [] }
  end
end

control 'cis-2.2.18' do
  impact 1.0
  title 'Ensure Create symbolic links is set to Administrators DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.18.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.2.18'
  describe user_right('SeCreateSymbolicLinkPrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.19' do
  impact 1.0
  title 'Ensure Create symbolic links is set to Administrators NT VIRTUAL MACHINE-Virtual Machines MS only | Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.19.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.2.19'
  describe user_right('SeCreateSymbolicLinkPrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.20' do
  impact 1.0
  title 'Ensure Debug programs is set to Administrators'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.20.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.20'
  describe user_right('SeDebugPrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.21' do
  impact 1.0
  title 'Ensure Deny access to this computer from the network to include Guests DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.21.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.2.21'
  describe user_right('SeDenyNetworkLogonRight') do
    it { should include 'Guests' }
  end
end

control 'cis-2.2.22' do
  impact 1.0
  title 'Ensure Deny access to this computer from the network to include Guests Local account and member of Administrators group MS only | Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.22.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.2.22'
  describe user_right('SeDenyNetworkLogonRight') do
    it { should include 'Guests' }
    it { should include 'Local Account' }
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.23' do
  impact 1.0
  title 'Ensure Deny log on as a batch job to include Guests'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.23.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.23'
  describe user_right('SeDenyBatchLogonRight') do
    it { should include 'Guests' }
  end
end

control 'cis-2.2.24' do
  impact 1.0
  title 'Ensure Deny log on as a service to include Guests'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.24.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.24'
  describe user_right('SeDenyServiceLogonRight') do
    it { should include 'Guests' }
  end
end

control 'cis-2.2.25' do
  impact 1.0
  title 'Ensure Deny log on locally to include Guests'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.25.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.25'
  describe user_right('SeDenyInteractiveLogonRight') do
    it { should include 'Guests' }
  end
end

control 'cis-2.2.26' do
  impact 1.0
  title 'Ensure Deny log on through Remote Desktop Services to include Guests DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.26.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.2.26'
  describe user_right('SeDenyRemoteInteractiveLogonRight') do
    it { should include 'Guests' }
  end
end

control 'cis-2.2.27' do
  impact 1.0
  title 'Ensure Deny log on through Remote Desktop Services is set to Guests Local account MS only | Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.27.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.2.27'
  describe user_right('SeDenyRemoteInteractiveLogonRight') do
    it { should include 'Guests' }
    it { should include 'Local Account' }
  end
end

control 'cis-2.2.28' do
  impact 1.0
  title 'Ensure Enable computer and user accounts to be trusted for delegation is set to Administrators DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.28.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.2.28'
  describe user_right('SeEnableDelegationPrivilege') do
    it { should include 'A' }
    it { should include 'd' }
    it { should include 'm' }
    it { should include 'i' }
    it { should include 'n' }
    it { should include 'i' }
    it { should include 's' }
    it { should include 't' }
    it { should include 'r' }
    it { should include 'a' }
    it { should include 't' }
    it { should include 'o' }
    it { should include 'r' }
    it { should include 's' }
  end
end

control 'cis-2.2.29' do
  impact 1.0
  title 'Ensure Enable computer and user accounts to be trusted for delegation is set to No One MS only | Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.29.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.2.29'
  describe user_right('SeEnableDelegationPrivilege') do
    it { should eq [] }
  end
end

control 'cis-2.2.30' do
  impact 1.0
  title 'Ensure Force shutdown from a remote system is set to Administrators'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.30.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.30'
  describe user_right('SeRemoteShutdownPrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.31' do
  impact 1.0
  title 'Ensure Generate security audits is set to LOCAL SERVICE, NETWORK SERVICE'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.31.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.31'
  describe user_right('SeAuditPrivilege') do
    it { should include 'LOCAL SERVICE' }
    it { should include 'NETWORK SERVICE' }
  end
end

control 'cis-2.2.32' do
  impact 1.0
  title 'Ensure Impersonate a client after authentication is set to Administrators LOCAL SERVICE NETWORK SERVICE SERVICE DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.32.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.2.32'
  describe user_right('SeImpersonatePrivilege') do
    it { should include 'Administrators' }
    it { should include 'LOCAL SERVICE' }
    it { should include 'NETWORK SERVICE' }
    it { should include 'SERVICE' }
  end
end

control 'cis-2.2.33' do
  impact 1.0
  title 'Ensure Impersonate a client after authentication is set to Administrators LOCAL SERVICE, NETWORK SERVICE, SERVICE and when the Web Server IIS Role with Web Services Role Service is installed IIS IUSRS MS only'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.33.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.2.33'
  describe user_right('SeImpersonatePrivilege') do
    it { should include 'Administrators' }
    it { should include 'LOCAL SERVICE' }
    it { should include 'NETWORK SERVICE' }
    it { should include 'SERVICE' }
  end
end

control 'cis-2.2.34' do
  impact 1.0
  title 'Ensure Increase scheduling priority is set to Administrators Window ManagerWindow Manager Group'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.34.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.34'
  describe user_right('SeIncreaseBasePriorityPrivilege') do
    it { should include '{' }
    it { should include '{' }
    it { should include ' ' }
    it { should include '[' }
    it { should include '\"' }
    it { should include 'A' }
    it { should include 'd' }
    it { should include 'm' }
    it { should include 'i' }
    it { should include 'n' }
    it { should include 'i' }
    it { should include 's' }
    it { should include 't' }
    it { should include 'r' }
    it { should include 'a' }
    it { should include 't' }
    it { should include 'o' }
    it { should include 'r' }
    it { should include 's' }
    it { should include '\"' }
    it { should include ']' }
    it { should include ' ' }
    it { should include 'i' }
    it { should include 'f' }
    it { should include ' ' }
    it { should include '(' }
    it { should include 'p' }
    it { should include 'r' }
    it { should include 'e' }
    it { should include 'l' }
    it { should include 'i' }
    it { should include 'm' }
    it { should include '_' }
    it { should include 'w' }
    it { should include 'i' }
    it { should include 'n' }
    it { should include 'd' }
    it { should include 'o' }
    it { should include 'w' }
    it { should include 's' }
    it { should include '_' }
    it { should include 'i' }
    it { should include 'n' }
    it { should include 's' }
    it { should include 't' }
    it { should include 'a' }
    it { should include 'l' }
    it { should include 'l' }
    it { should include 'a' }
    it { should include 't' }
    it { should include 'i' }
    it { should include 'o' }
    it { should include 'n' }
    it { should include '_' }
    it { should include 't' }
    it { should include 'y' }
    it { should include 'p' }
    it { should include 'e' }
    it { should include ' ' }
    it { should include '=' }
    it { should include '=' }
    it { should include ' ' }
    it { should include '\"' }
    it { should include 'S' }
    it { should include 'e' }
    it { should include 'r' }
    it { should include 'v' }
    it { should include 'e' }
    it { should include 'r' }
    it { should include ' ' }
    it { should include 'C' }
    it { should include 'o' }
    it { should include 'r' }
    it { should include 'e' }
    it { should include '\"' }
    it { should include ')' }
    it { should include ' ' }
    it { should include 'e' }
    it { should include 'l' }
    it { should include 's' }
    it { should include 'e' }
    it { should include ' ' }
    it { should include '(' }
    it { should include '[' }
    it { should include '\"' }
    it { should include 'A' }
    it { should include 'd' }
    it { should include 'm' }
    it { should include 'i' }
    it { should include 'n' }
    it { should include 'i' }
    it { should include 's' }
    it { should include 't' }
    it { should include 'r' }
    it { should include 'a' }
    it { should include 't' }
    it { should include 'o' }
    it { should include 'r' }
    it { should include 's' }
    it { should include '\"' }
    it { should include ',' }
    it { should include ' ' }
    it { should include '\"' }
    it { should include 'W' }
    it { should include 'i' }
    it { should include 'n' }
    it { should include 'd' }
    it { should include 'o' }
    it { should include 'w' }
    it { should include ' ' }
    it { should include 'M' }
    it { should include 'a' }
    it { should include 'n' }
    it { should include 'a' }
    it { should include 'g' }
    it { should include 'e' }
    it { should include 'r' }
    it { should include '\\' }
    it { should include 'W' }
    it { should include 'i' }
    it { should include 'n' }
    it { should include 'd' }
    it { should include 'o' }
    it { should include 'w' }
    it { should include ' ' }
    it { should include 'M' }
    it { should include 'a' }
    it { should include 'n' }
    it { should include 'a' }
    it { should include 'g' }
    it { should include 'e' }
    it { should include 'r' }
    it { should include ' ' }
    it { should include 'G' }
    it { should include 'r' }
    it { should include 'o' }
    it { should include 'u' }
    it { should include 'p' }
    it { should include '\"' }
    it { should include ']' }
    it { should include ')' }
    it { should include ' ' }
    it { should include '}' }
    it { should include '}' }
  end
end

control 'cis-2.2.35' do
  impact 1.0
  title 'Ensure Load and unload device drivers is set to Administrators'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.35.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.35'
  describe user_right('SeLoadDriverPrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.36' do
  impact 1.0
  title 'Ensure Lock pages in memory is set to No One'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.36.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.36'
  describe user_right('SeLockMemoryPrivilege') do
    it { should eq [] }
  end
end

control 'cis-2.2.37' do
  impact 1.0
  title 'Ensure Log on as a batch job is set to Administrators DC Only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.37.'
  only_if('Level 2 controls disabled') { input('run_level_2') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.2.37'
  describe user_right('SeBatchLogonRight') do
    it { should include 'A' }
    it { should include 'd' }
    it { should include 'm' }
    it { should include 'i' }
    it { should include 'n' }
    it { should include 'i' }
    it { should include 's' }
    it { should include 't' }
    it { should include 'r' }
    it { should include 'a' }
    it { should include 't' }
    it { should include 'o' }
    it { should include 'r' }
    it { should include 's' }
  end
end

control 'cis-2.2.38' do
  impact 1.0
  title "Ensure 'Manage auditing and security log' is set to Administrators | Domain Controller"
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.38.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.2.38'
  describe user_right('SeSecurityPrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.39' do
  impact 1.0
  title "Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only) | Member Server"
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.39.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.2.39'
  describe user_right('SeSecurityPrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.40' do
  impact 1.0
  title 'Ensure Modify an object label is set to No One'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.40.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.40'
  describe user_right('SeReLabelPrivilege') do
    it { should eq [] }
  end
end

control 'cis-2.2.41' do
  impact 1.0
  title 'Ensure Modify firmware environment values is set to Administrators'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.41.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.41'
  describe user_right('SeSystemEnvironmentPrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.42' do
  impact 1.0
  title 'Ensure Perform volume maintenance tasks is set to Administrators'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.42.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.42'
  describe user_right('SeManageVolumePrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.43' do
  impact 1.0
  title 'Ensure Profile single process is set to Administrators'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.43.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.43'
  describe user_right('SeProfileSingleProcessPrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.44' do
  impact 1.0
  title 'Ensure Profile system performance is set to Administrators NT SERVICE.WdiServiceHost'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.44.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.44'
  describe user_right('SeSystemProfilePrivilege') do
    it { should include 'Administrators' }
    it { should include 'NT SERVICE\\WdiServiceHost' }
  end
end

control 'cis-2.2.45' do
  impact 1.0
  title 'Ensure Replace a process level token is set to LOCAL SERVICE NETWORK SERVICE'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.45.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.45'
  describe user_right('SeAssignPrimaryTokenPrivilege') do
    it { should include 'LOCAL SERVICE' }
    it { should include 'NETWORK SERVICE' }
  end
end

control 'cis-2.2.46' do
  impact 1.0
  title 'Ensure Restore files and directories is set to Administrators'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.46.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.46'
  describe user_right('SeRestorePrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.47' do
  impact 1.0
  title 'Ensure Shut down the system is set to Administrators'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.47.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.47'
  describe user_right('SeShutdownPrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.2.48' do
  impact 1.0
  title 'Ensure Synchronize directory service data is set to No One DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.48.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.2.48'
  describe user_right('SeSyncAgentPrivilege') do
    it { should eq [] }
  end
end

control 'cis-2.2.49' do
  impact 1.0
  title 'Ensure Take ownership of files or other objects is set to Administrators'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.2.49.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.2.49'
  describe user_right('SeTakeOwnershipPrivilege') do
    it { should include 'Administrators' }
  end
end

control 'cis-2.3.1.1' do
  impact 1.0
  title 'Ensure Accounts Guest account status is set to Disabled MS only | Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.1.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.3.1.1'
  describe local_security_policy do
    its('EnableGuestAccount') { should cmp 0 }
  end
end

control 'cis-2.3.1.2' do
  impact 1.0
  title 'Ensure Accounts Limit local account use of blank passwords to console logon only is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.1.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.1.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('LimitBlankPasswordUse') { should cmp 1 }
  end
end

control 'cis-2.3.1.3' do
  impact 1.0
  title 'Configure Accounts Rename administrator account'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.1.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.1.3'
  describe local_security_policy do
    its('newadministratorname') { should eq 'adminchangethis' }
  end
end

control 'cis-2.3.1.4' do
  impact 1.0
  title 'Configure Accounts Rename guest account'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.1.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.1.4'
  describe local_security_policy do
    its('NewGuestName') { should eq 'guestchangethis' }
  end
end

control 'cis-2.3.2.1' do
  impact 1.0
  title 'Ensure Audit Force audit policy subcategory settings Windows Vista or later to override audit policy category settings is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.2.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.2.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('SCENoApplyLegacyAuditPolicy') { should cmp 1 }
  end
end

control 'cis-2.3.2.2' do
  impact 1.0
  title 'Ensure Audit Shut down system immediately if unable to log security audits is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.2.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.2.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('CrashOnAuditFail') { should cmp 0 }
  end
end

control 'cis-2.3.4.1' do
  impact 1.0
  title 'Ensure Devices Prevent users from installing printer drivers is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.4.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.4.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\Lanman Print Services\\Servers') do
    its('AddPrinterDrivers') { should cmp 1 }
  end
end

control 'cis-2.3.5.1' do
  impact 1.0
  title 'Ensure Domain controller Allow server operators to schedule tasks is set to Disabled DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.5.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.3.5.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('SubmitControl') { should cmp 0 }
  end
end

control 'cis-2.3.5.2' do
  impact 1.0
  title 'Ensure Domain controller Allow vulnerable Netlogon secure channel connections is set to Not Configured DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.5.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.3.5.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('VulnerableChannelAllowList') { should cmp 0 }
  end
end

control 'cis-2.3.5.3' do
  impact 1.0
  title 'Ensure Domain controller LDAP server channel binding token requirements is set to Always DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.5.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.3.5.3'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters') do
    its('LdapEnforceChannelBinding') { should cmp 2 }
  end
end

control 'cis-2.3.5.4' do
  impact 1.0
  title 'Ensure Domain controller LDAP server signing requirements is set to Require signing DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.5.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.3.5.4'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters') do
    its('LDAPServerIntegrity') { should cmp 2 }
  end
end

control 'cis-2.3.5.5' do
  impact 1.0
  title 'Ensure Domain controller LDAP server signing requirements Enforcement is set to Enabled | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.5.5.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.3.5.5'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters') do
    its('LDAPServerForceIntegrity') { should cmp 1 }
  end
end

control 'cis-2.3.5.6' do
  impact 1.0
  title 'Ensure Domain controller Refuse machine account password changes is set to Disabled DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.5.6.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.3.5.6'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('RefusePasswordChange') { should cmp 0 }
  end
end

control 'cis-2.3.6.1' do
  impact 1.0
  title 'Ensure Domain member Digitally encrypt or sign secure channel data always is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.6.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'domain_member' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.6.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('RequireSignOrSeal') { should cmp 1 }
  end
end

control 'cis-2.3.6.2' do
  impact 1.0
  title 'Ensure Domain member Digitally encrypt secure channel data when possible is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.6.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'domain_member' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.6.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('SealSecureChannel') { should cmp 1 }
  end
end

control 'cis-2.3.6.3' do
  impact 1.0
  title 'Ensure Domain member Digitally sign secure channel data when possible is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.6.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'domain_member' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.6.3'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('SignSecureChannel') { should cmp 1 }
  end
end

control 'cis-2.3.6.4' do
  impact 1.0
  title 'Ensure Domain member Disable machine account password changes is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.6.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'domain_member' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.6.4'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('DisablePasswordChange') { should cmp 0 }
  end
end

control 'cis-2.3.6.5' do
  impact 1.0
  title 'Ensure Domain member Maximum machine account password age is set to 30 or fewer days but not 0'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.6.5.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'domain_member' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.6.5'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('MaximumPasswordAge') { should cmp 30 }
  end
end

control 'cis-2.3.6.6' do
  impact 1.0
  title 'Ensure Domain member Require strong Windows 2000 or later session key is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.6.6.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'domain_member' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.6.6'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('RequireStrongKey') { should cmp 1 }
  end
end

control 'cis-2.3.7.1' do
  impact 1.0
  title 'Ensure Interactive logon Do not require CTRL+ALT+DEL is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.7.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.7.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('DisableCAD') { should cmp 0 }
  end
end

control 'cis-2.3.7.2' do
  impact 1.0
  title 'Ensure Interactive logon Do not display last signed-in is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.7.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.7.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('DontDisplayLastUserName') { should cmp 1 }
  end
end

control 'cis-2.3.7.3' do
  impact 1.0
  title 'Ensure Interactive logon Machine inactivity limit is set to 900 or fewer seconds but not 0'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.7.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.7.3'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('InactivityTimeoutSecs') { should cmp 900 }
  end
end

control 'cis-2.3.7.4' do
  impact 1.0
  title 'Configure Interactive logon Message text for users attempting to log on'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.7.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.7.4'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('LegalNoticeText') { should eq 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
' }
  end
end

control 'cis-2.3.7.5' do
  impact 1.0
  title 'Configure Interactive logon Message title for users attempting to log on'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.7.5.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.7.5'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('LegalNoticeCaption') { should eq 'DoD Notice and Consent Banner' }
  end
end

control 'cis-2.3.7.6' do
  impact 1.0
  title 'Ensure Interactive logon Number of previous logons to cache in case domain controller is not available is set to 4 or fewer logons MS only | Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.7.6.'
  only_if('Level 2 controls disabled') { input('run_level_2') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.3.7.6'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Nt\\CurrentVersion\\Winlogon') do
    its('CachedLogonsCount') { should cmp 1 }
  end
end

control 'cis-2.3.7.7' do
  impact 1.0
  title 'Ensure Interactive logon Prompt user to change password before expiration is set to between 5 and 14 days'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.7.7.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.7.7'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Nt\\CurrentVersion\\Winlogon') do
    its('PasswordExpiryWarning') { should cmp 14 }
  end
end

control 'cis-2.3.7.8' do
  impact 1.0
  title 'Ensure Interactive logon Require Domain Controller Authentication to unlock workstation is set to Enabled MS only | Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.7.8.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.3.7.8'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Nt\\CurrentVersion\\Winlogon') do
    its('ForceUnlockLogon') { should cmp 1 }
  end
end

control 'cis-2.3.7.9' do
  impact 1.0
  title 'Ensure Interactive logon Smart card removal behavior is set to Lock Workstation or higher.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.7.9.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.7.9'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Nt\\CurrentVersion\\Winlogon') do
    its('ScRemoveOption') { should cmp 1 }
  end
end

control 'cis-2.3.8.1' do
  impact 1.0
  title 'Ensure Microsoft network client Digitally sign communications always is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.8.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.8.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    its('RequireSecuritySignature') { should cmp 1 }
  end
end

control 'cis-2.3.8.2' do
  impact 1.0
  title 'Ensure Microsoft network client Digitally sign communications if server agrees is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.8.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.8.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    its('EnableSecuritySignature') { should cmp 1 }
  end
end

control 'cis-2.3.8.3' do
  impact 1.0
  title 'Ensure Microsoft network client Send unencrypted password to third-party SMB servers is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.8.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.8.3'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    its('EnablePlainTextPassword') { should cmp 0 }
  end
end

control 'cis-2.3.9.1' do
  impact 1.0
  title 'Ensure Microsoft network server Amount of idle time required before suspending session is set to 15 or fewer minutes.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.9.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.9.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Lanmanserver\\Parameters') do
    its('AutoDisconnect') { should cmp 15 }
  end
end

control 'cis-2.3.9.2' do
  impact 1.0
  title 'Ensure Microsoft network server Digitally sign communications always is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.9.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.9.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Lanmanserver\\Parameters') do
    its('RequireSecuritySignature') { should cmp 1 }
  end
end

control 'cis-2.3.9.3' do
  impact 1.0
  title 'Ensure Microsoft network server Digitally sign communications if client agrees is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.9.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.9.3'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Lanmanserver\\Parameters') do
    its('EnableSecuritySignature') { should cmp 1 }
  end
end

control 'cis-2.3.9.4' do
  impact 1.0
  title 'Ensure Microsoft network server Disconnect clients when logon hours expire is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.9.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.9.4'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Lanmanserver\\Parameters') do
    its('EnableForcedLogoff') { should cmp 1 }
  end
end

control 'cis-2.3.9.5' do
  impact 1.0
  title 'Ensure Microsoft network server Server SPN target name validation level is set to Accept if provided by client or higher. | MS Only'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.9.5.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.3.9.5'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('SMBServerNameHardeningLevel') { should cmp 1 }
  end
end

control 'cis-2.3.10.1' do
  impact 1.0
  title 'Ensure Network access Allow anonymous SID/Name translation is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.10.1'
  describe local_security_policy do
    its('LSAAnonymousNameLookup') { should cmp 0 }
  end
end

control 'cis-2.3.10.2' do
  impact 1.0
  title 'Ensure Network access Do not allow anonymous enumeration of SAM accounts is set to Enabled MS only | Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.3.10.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('RestrictAnonymousSAM') { should cmp 1 }
  end
end

control 'cis-2.3.10.3' do
  impact 1.0
  title 'Ensure Network access Do not allow anonymous enumeration of SAM accounts and shares is set to Enabled MS only | Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.3.10.3'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('RestrictAnonymous') { should cmp 1 }
  end
end

control 'cis-2.3.10.4' do
  impact 1.0
  title 'Ensure Network access Do not allow storage of passwords and credentials for network authentication is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.4.'
  only_if('Level 2 controls disabled') { input('run_level_2') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.10.4'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('DisableDomainCreds') { should cmp 1 }
  end
end

control 'cis-2.3.10.5' do
  impact 1.0
  title 'Ensure Network access Let Everyone permissions apply to anonymous users is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.5.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.10.5'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('EveryoneIncludesAnonymous') { should cmp 0 }
  end
end

control 'cis-2.3.10.6' do
  impact 1.0
  title 'Configure Network access Named Pipes that can be accessed anonymously DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.6.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.3.10.6'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('NullSessionPipes') { should cmp ['LSARPC', 'NETLOGON', 'SAMR'] }
  end
end

control 'cis-2.3.10.7' do
  impact 1.0
  title 'Configure Network access Named Pipes that can be accessed anonymously MS only | Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.7.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.3.10.7'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('NullSessionPipes') { should eq '' }
  end
end

control 'cis-2.3.10.8' do
  impact 1.0
  title 'Configure Network access Remotely accessible registry paths'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.8.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.10.8'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Securepipeservers\\Winreg\\AllowedExactpaths') do
    its('Machine') { should cmp ['SYSTEM\\\\CurrentControlSet\\\\Control\\\\ProductOptions', 'SYSTEM\\\\CurrentControlSet\\\\Control\\\\Server Applications', 'SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion'] }
  end
end

control 'cis-2.3.10.9' do
  impact 1.0
  title 'Configure Network access Remotely accessible registry paths and sub-paths'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.9.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.10.9'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Securepipeservers\\Winreg\\Allowedpaths') do
    its('Machine') { should eq '{{ rule_2_3_10_9_remote_registry_paths }}' }
  end
end

control 'cis-2.3.10.10' do
  impact 1.0
  title 'Ensure Network access Restrict anonymous access to Named Pipes and Shares is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.10.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.10.10'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Lanmanserver\\Parameters') do
    its('RestrictNullSessAccess') { should cmp 1 }
  end
end

control 'cis-2.3.10.11' do
  impact 1.0
  title 'Ensure Network access Restrict clients allowed to make remote calls to SAM is set to Administrators Remote Access Allow MS only | Member Server'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.11.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }
  tag cis_id: '2.3.10.11'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('RestrictRemoteSAM') { should eq 'O:BAG:BAD:(A;;RC;;;BA)' }
  end
end

control 'cis-2.3.10.12' do
  impact 1.0
  title 'Ensure Network access Shares that can be accessed anonymously is set to None'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.12.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.10.12'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Lanmanserver\\Parameters') do
    its('NullSessionShares') { should eq '' }
  end
end

control 'cis-2.3.10.13' do
  impact 1.0
  title 'Ensure Network access Sharing and security model for local accounts is set to Classic - local users authenticate as themselves'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.10.13.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.10.13'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('ForceGuest') { should cmp 0 }
  end
end

control 'cis-2.3.11.1' do
  impact 1.0
  title 'Ensure Network security Allow Local System to use computer identity for NTLM is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('UseMachineId') { should cmp 1 }
  end
end

control 'cis-2.3.11.2' do
  impact 1.0
  title 'Ensure Network security Allow LocalSystem NULL session fallback is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Msv1_0') do
    its('AllowNullSessionFallback') { should cmp 0 }
  end
end

control 'cis-2.3.11.3' do
  impact 1.0
  title 'Ensure Network Security Allow PKU2U authentication requests to this computer to use online identities is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.3'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Pku2U') do
    its('AllowOnlineID') { should cmp 0 }
  end
end

control 'cis-2.3.11.4' do
  impact 1.0
  title 'Ensure Network security Configure encryption types allowed for Kerberos is set to AES128 HMAC SHA1 AES256 HMAC SHA1 Future encryption types'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.4'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters') do
    its('SupportedEncryptionTypes') { should cmp 2147483644 }
  end
end

control 'cis-2.3.11.5' do
  impact 1.0
  title 'Ensure Network security Do not store LAN Manager hash value on next password change is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.5.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.5'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('NoLMHash') { should cmp 1 }
  end
end

control 'cis-2.3.11.6' do
  impact 1.0
  title 'Ensure Network security Force logoff when logon hours expire is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.6.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.6'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('EnableForcedLogOff') { should cmp 1 }
  end
end

control 'cis-2.3.11.7' do
  impact 1.0
  title 'Ensure Network security LAN Manager authentication level is set to Send NTLMv2 response only. Refuse LM NTLM'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.7.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.7'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('LMCompatibilityLevel') { should cmp 5 }
  end
end

control 'cis-2.3.11.8' do
  impact 1.0
  title "Ensure 'Network security: LDAP client encryption requirements' is set to 'Negotiate sealing' or higher."
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.8.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.8'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Ldap') do
    its('LDAPClientConfidentiality') { should cmp 1 }
  end
end

control 'cis-2.3.11.9' do
  impact 1.0
  title 'Ensure Network security LDAP client signing requirements is set to Negotiate signing or higher.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.9.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.9'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Ldap') do
    its('LDAPClientIntegrity') { should cmp 1 }
  end
end

control 'cis-2.3.11.10' do
  impact 1.0
  title 'Ensure Network security Minimum session security for NTLM SSP based including secure RPC clients is set to Require NTLMv2 session security Require 128-bit encryption'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.10.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.10'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Msv1_0') do
    its('NTLMMinClientSec') { should cmp 537395200 }
  end
end

control 'cis-2.3.11.11' do
  impact 1.0
  title 'Ensure Network security Minimum session security for NTLM SSP based including secure RPC servers is set to Require NTLMv2 session security Require 128-bit encryption'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.11.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.11'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Msv1_0') do
    its('NTLMMinServerSec') { should cmp 537395200 }
  end
end

control 'cis-2.3.11.12' do
  impact 1.0
  title 'Ensure Network security: Restrict NTLM: Audit Incoming NTLM Traffic is set to Enable auditing for all accounts'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.12.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.12'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    its('AuditReceivingNTLMTraffic') { should cmp 2 }
  end
end

control 'cis-2.3.11.13' do
  impact 1.0
  title 'Ensure Network security: Restrict NTLM: Audit NTLM authentication in this domain is set to Enable all DC Only'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.13.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }
  tag cis_id: '2.3.11.13'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('AuditNTLMInDomain') { should cmp 7 }
  end
end

control 'cis-2.3.11.14' do
  impact 1.0
  title 'Ensure Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers is set to Audit all or higher.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.11.14.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.11.14'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    its('RestrictSendingNTLMTraffic') { should cmp 2 }
  end
end

control 'cis-2.3.13.1' do
  impact 1.0
  title 'Ensure Shutdown Allow system to be shut down without having to log on is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.13.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.13.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('ShutdownWithoutLogon') { should cmp 0 }
  end
end

control 'cis-2.3.15.1' do
  impact 1.0
  title 'Ensure System objects Require case insensitivity for non-Windows subsystems is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.15.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.15.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel') do
    its('ObCaseInsensitive') { should cmp 1 }
  end
end

control 'cis-2.3.15.2' do
  impact 1.0
  title 'Ensure System objects Strengthen default permissions of internal system objects e.g. Symbolic Links is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.15.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.15.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager') do
    its('ProtectionMode') { should cmp 1 }
  end
end

control 'cis-2.3.17.1' do
  impact 1.0
  title 'Ensure User Account Control Admin Approval Mode for the Built-in Administrator account is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.17.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.17.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('FilterAdministratorToken') { should cmp 1 }
  end
end

control 'cis-2.3.17.2' do
  impact 1.0
  title "Ensure User Account Control Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop or higher"
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.17.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.17.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('ConsentPromptBehaviorAdmin') { should cmp 2 }
  end
end

control 'cis-2.3.17.3' do
  impact 1.0
  title 'Ensure User Account Control Behavior of the elevation prompt for standard users is set to Automatically deny elevation requests'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.17.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.17.3'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('ConsentPromptBehaviorUser') { should cmp 0 }
  end
end

control 'cis-2.3.17.4' do
  impact 1.0
  title 'Ensure User Account Control Detect application installations and prompt for elevation is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.17.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.17.4'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('EnableInstallerDetection') { should cmp 1 }
  end
end

control 'cis-2.3.17.5' do
  impact 1.0
  title 'Ensure User Account Control Only elevate UIAccess applications that are installed in secure locations is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.17.5.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.17.5'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('EnableSecureUIAPaths') { should cmp 1 }
  end
end

control 'cis-2.3.17.6' do
  impact 1.0
  title 'Ensure User Account Control Run all administrators in Admin Approval Mode is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.17.6.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.17.6'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('EnableLUA') { should cmp 1 }
  end
end

control 'cis-2.3.17.7' do
  impact 1.0
  title 'Ensure User Account Control Switch to the secure desktop when prompting for elevation is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.17.7.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.17.7'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('PromptOnSecureDesktop') { should cmp 1 }
  end
end

control 'cis-2.3.17.8' do
  impact 1.0
  title 'Ensure User Account Control Virtualize file and registry write failures to per-user locations is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 2.3.17.8.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '2.3.17.8'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('EnableVirtualization') { should cmp 1 }
  end
end
