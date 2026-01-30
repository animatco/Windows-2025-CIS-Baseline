# frozen_string_literal: true
###############################################
#  CIS Microsoft Windows Server 2025 Benchmark
#  Section 01 — Account Policies
###############################################

require_relative File.join(__dir__, '..', 'libraries', 'cis_password_policy')
require_relative File.join(__dir__, '..', 'libraries', 'cis_privilege')
require_relative File.join(__dir__, '..', 'libraries', 'cis_audit_policy')
require_relative File.join(__dir__, '..', 'libraries', 'cis_security_options')

require_relative File.join(__dir__, '..', 'libraries', 'local_policy_export')
require_relative File.join(__dir__, '..', 'libraries', 'user_right')


only_if("Section 01 disabled by input") do
  input("run_section_01")
end

#
# 1.1.1 Enforce password history
#
control 'cis-1.1.1' do
  impact 1.0
  title 'Ensure Enforce password history is set to 24 or more passwords.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '1.1.1'

  describe local_security_policy do
    its('PasswordHistorySize') { should cmp >= 24 }
  end
end

#
# 1.1.2 Maximum password age
#
control 'cis-1.1.2' do
  impact 1.0
  title 'Ensure Maximum password age is set to 365 or fewer days but not 0'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.2.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '1.1.2'

  describe 'Maximum password age (days)' do
    subject { CisPasswordPolicy.max_age_days(local_security_policy.MaximumPasswordAge) }
    it { should be <= 365 }
    it { should be > 0 }
  end
end

#
# 1.1.3 Minimum password age
#
control 'cis-1.1.3' do
  impact 1.0
  title 'Ensure Minimum password age is set to 1 or more days'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.3.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '1.1.3'

  describe 'Minimum password age (days)' do
    subject { CisPasswordPolicy.min_age_days(local_security_policy.MinimumPasswordAge) }
    it { should cmp >= 1 }
  end
end

#
# 1.1.6 Relax minimum password length limits
#
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

#
# 1.1.4 Minimum password length
#
control 'cis-1.1.4' do
  impact 1.0
  title 'Ensure Minimum password length is set to 14 or more characters'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.4.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '1.1.4'

  describe local_security_policy do
    its('MinimumPasswordLength') { should cmp >= 14 }
  end
end

#
# 1.1.5 Password complexity
#
control 'cis-1.1.5' do
  impact 1.0
  title 'Ensure Password must meet complexity requirements is set to Enabled.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.5.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '1.1.5'

  describe 'Password complexity enabled' do
    subject { CisPasswordPolicy.complexity_enabled?(local_security_policy.PasswordComplexity) }
    it { should cmp true }
  end
end

#
# 1.1.7 Reversible encryption
#
control 'cis-1.1.7' do
  impact 1.0
  title 'Ensure Store passwords using reversible encryption is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.1.7.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '1.1.7'

  describe 'Reversible encryption disabled' do
    subject { CisPasswordPolicy.reversible_encryption_disabled?(local_security_policy.ClearTextPassword) }
    it { should cmp true }
  end
end

#
# 1.2.2 Account lockout threshold
#
control 'cis-1.2.2' do
  impact 1.0
  title 'Ensure Account lockout threshold is set to 5 or fewer invalid logon attempt(s), but not 0.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.2.2.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '1.2.2'

  describe 'Lockout threshold' do
    subject { CisPasswordPolicy.lockout_threshold(local_security_policy.LockoutBadCount) }
    it { should cmp <= 5 }
    it { should_not cmp 0 }
  end
end

#
# 1.2.4 Reset lockout counter
#
control 'cis-1.2.4' do
  impact 1.0
  title 'Ensure Reset account lockout counter after is set to 15 or more minutes.'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.2.4.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '1.2.4'

  describe 'Reset lockout counter (minutes)' do
    subject { CisPasswordPolicy.reset_lockout_minutes(local_security_policy.ResetLockoutCount) }
    it { should cmp >= 15 }
  end
end

#
# 1.2.1 Lockout duration
#
control 'cis-1.2.1' do
  impact 1.0
  title 'Ensure Account lockout duration is set to 15 or more minutes'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.2.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '1.2.1'

  describe 'Lockout duration (minutes)' do
    subject { CisPasswordPolicy.lockout_minutes(local_security_policy.LockoutDuration) }
    it { should cmp >= 15 }
  end
end

#
# 1.2.3 Allow Administrator account lockout
#
control 'cis-1.2.3' do
  impact 1.0
  title 'Ensure Allow Administrator account lockout is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 1.2.3.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Not a member server') { input('server_role') == 'member_server' }

  tag cis_id: '1.2.3'

  describe 'Administrator lockout enabled' do
    subject { CisPasswordPolicy.admin_lockout_enabled?(local_security_policy.AllowAdministratorLockout) }
    it { should cmp true }
  end
end
