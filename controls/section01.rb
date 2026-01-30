# frozen_string_literal: true

## Auto-generated from ansible-lockdown/Windows-2025-CIS Ansible role
## Source section: section01

control 'cis-1.1.1' do
  impact 1.0
  title 'Ensure Enforce password history is set to 24 or more passwords.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') do
    %w[domain_controller member_server].include?(input('server_role'))
  end

  tag cis_id: '1.1.1'

  describe local_security_policy do
    its('PasswordHistorySize') { should cmp >= 24 }
  end
end

control 'cis-1.1.2' do
  impact 1.0
  title 'Ensure Maximum password age is set to 365 or fewer days but not 0'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.2.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') do
    %w[domain_controller member_server].include?(input('server_role'))
  end

  tag cis_id: '1.1.2'

  describe 'Maximum password age (days)' do
    subject { CisHelpers.cis_password_age_days(local_security_policy.MaximumPasswordAge) }
    it { should be <= 365 }
    it { should be > 0 }
  end
end

control 'cis-1.1.3' do
  impact 1.0
  title 'Ensure Minimum password age is set to 1 or more days'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.3.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') do
    %w[domain_controller member_server].include?(input('server_role'))
  end

  tag cis_id: '1.1.3'

  describe local_security_policy do
    its('MinimumPasswordAge') { should cmp >= 1 }
  end
end

control 'cis-1.1.6' do
  impact 1.0
  title 'Ensure Relax minimum password length limits is set to Enabled.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.6.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Not a member server') { input('server_role') == 'member_server' }

  tag cis_id: '1.1.6'

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SAM') do
    its('RelaxMinimumPasswordLengthLimits') { should cmp 1 }
  end
end

control 'cis-1.1.4' do
  impact 1.0
  title 'Ensure Minimum password length is set to 14 or more characters'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.4.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') do
    %w[domain_controller member_server].include?(input('server_role'))
  end

  tag cis_id: '1.1.4'

  describe local_security_policy do
    its('MinimumPasswordLength') { should cmp >= 14 }
  end
end

control 'cis-1.1.5' do
  impact 1.0
  title 'Ensure Password must meet complexity requirements is set to Enabled.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.5.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') do
    %w[domain_controller member_server].include?(input('server_role'))
  end

  tag cis_id: '1.1.5'

  describe local_security_policy do
    its('PasswordComplexity') { should cmp 1 }
  end
end

control 'cis-1.1.7' do
  impact 1.0
  title 'Ensure Store passwords using reversible encryption is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.7.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') do
    %w[domain_controller member_server].include?(input('server_role'))
  end

  tag cis_id: '1.1.7'

  describe local_security_policy do
    its('ClearTextPassword') { should cmp 0 }
  end
end

control 'cis-1.2.2' do
  impact 1.0
  title 'Ensure Account lockout threshold is set to 5 or fewer invalid logon attempt(s), but not 0.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.2.2.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') do
    %w[domain_controller member_server].include?(input('server_role'))
  end

  tag cis_id: '1.2.2'

  describe local_security_policy do
    its('LockoutBadCount') { should cmp <= 5 }
    its('LockoutBadCount') { should_not cmp 0 }
  end
end

control 'cis-1.2.4' do
  impact 1.0
  title 'Ensure Reset account lockout counter after is set to 15 or more minutes.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.2.4.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') do
    %w[domain_controller member_server].include?(input('server_role'))
  end

  tag cis_id: '1.2.4'

  describe local_security_policy do
    its('ResetLockoutCount') { should cmp >= 15 }
  end
end

control 'cis-1.2.1' do
  impact 1.0
  title 'Ensure Account lockout duration is set to 15 or more minutes'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.2.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') do
    %w[domain_controller member_server].include?(input('server_role'))
  end

  tag cis_id: '1.2.1'

  describe local_security_policy do
    its('LockoutDuration') { should cmp >= 15 }
  end
end

control 'cis-1.2.3' do
  impact 1.0
  title 'Ensure Allow Administrator account lockout is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.2.3.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Not a member server') { input('server_role') == 'member_server' }

  tag cis_id: '1.2.3'

  describe local_security_policy do
    its('AllowAdministratorLockout') { should cmp 1 }
  end
end
