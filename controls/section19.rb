# frozen_string_literal: true
###############################################
#  CIS Microsoft Windows Server 2025 Benchmark
#  Section 19 — Administrative Templates (User)
###############################################

require inspec.profile.file('libraries/cis_password_policy.rb')
require inspec.profile.file('libraries/cis_privilege.rb')
require inspec.profile.file('libraries/cis_audit_policy.rb')
require inspec.profile.file('libraries/cis_security_options.rb')
require inspec.profile.file('libraries/local_policy_export.rb')
require inspec.profile.file('libraries/user_right.rb')

only_if("Section 19 disabled by input") do
  input("run_section_19")
end

control 'cis-19.5.1.1' do
  impact 1.0
  title 'Ensure Turn off toast notifications on the lock screen is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 19.5.1.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Section 19 controls disabled') { input('run_section_19', value: true) }

role = input('server_role', value: '').to_s.strip.downcase
  only_if("Not applicable: requires server_role member_server or domain_controller (server_role=#{role})") do
    %w[member_server domain_controller].include?(role)
  end
  tag cis_id: '19.5.1.1'
  describe registry_key('HKEY_USERS\\{{ item }}\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Pushnotifications') do
    its('NoToastApplicationNotificationOnLockScreen') { should cmp 1 }
  end
end

control 'cis-19.6.6.1.1' do
  impact 1.0
  title 'Ensure Turn off Help Experience Improvement Program is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 19.6.6.1.1.'
  only_if('Level 2 controls disabled') { input('run_level_2') }
  only_if('Section 19 controls disabled') { input('run_section_19', value: true) }

role = input('server_role', value: '').to_s.strip.downcase
  only_if("Not applicable: requires server_role member_server or domain_controller (server_role=#{role})") do
    %w[member_server domain_controller].include?(role)
  end
  tag cis_id: '19.6.6.1.1'
  describe registry_key('HKEY_USERS\\{{ item }}\\SOFTWARE\\Policies\\Microsoft\\Assistance\\Client\\1.0') do
    its('NoImplicitFeedback') { should cmp 1 }
  end
end

control 'cis-19.7.5.1' do
  impact 1.0
  title 'Ensure Do not preserve zone information in file attachments is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 19.7.5.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Section 19 controls disabled') { input('run_section_19', value: true) }

role = input('server_role', value: '').to_s.strip.downcase
  only_if("Not applicable: requires server_role member_server or domain_controller (server_role=#{role})") do
    %w[member_server domain_controller].include?(role)
  end
  tag cis_id: '19.7.5.1'
  describe registry_key('HKEY_USERS\\{{ item }}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments') do
    its('SaveZoneInformation') { should cmp 2 }
  end
end

control 'cis-19.7.5.2' do
  impact 1.0
  title 'Ensure Notify antivirus programs when opening attachments is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 19.7.5.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Section 19 controls disabled') { input('run_section_19', value: true) }

role = input('server_role', value: '').to_s.strip.downcase
  only_if("Not applicable: requires server_role member_server or domain_controller (server_role=#{role})") do
    %w[member_server domain_controller].include?(role)
  end
  tag cis_id: '19.7.5.2'
  describe registry_key('HKEY_USERS\\{{ item }}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments') do
    its('ScanWithAntiVirus') { should cmp 3 }
  end
end

control 'cis-19.7.8.1' do
  impact 1.0
  title 'Ensure Configure Windows spotlight on lock screen is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 19.7.8.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Section 19 controls disabled') { input('run_section_19', value: true) }

role = input('server_role', value: '').to_s.strip.downcase
  only_if("Not applicable: requires server_role member_server or domain_controller (server_role=#{role})") do
    %w[member_server domain_controller].include?(role)
  end
  tag cis_id: '19.7.8.1'
  describe registry_key('HKEY_USERS\\{{ item }}\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent') do
    its('ConfigureWindowsSpotlight') { should cmp 2 }
  end
end

control 'cis-19.7.8.2' do
  impact 1.0
  title 'Ensure Do not suggest third-party content in Windows spotlight is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 19.7.8.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Section 19 controls disabled') { input('run_section_19', value: true) }

role = input('server_role', value: '').to_s.strip.downcase
  only_if("Not applicable: requires server_role member_server or domain_controller (server_role=#{role})") do
    %w[member_server domain_controller].include?(role)
  end
  tag cis_id: '19.7.8.2'
  describe registry_key('HKEY_USERS\\{{ item }}\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent') do
    its('DisableThirdPartySuggestions') { should cmp 1 }
  end
end

control 'cis-19.7.8.3' do
  impact 1.0
  title 'Ensure Do not use diagnostic data for tailored experiences is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 19.7.8.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Section 19 controls disabled') { input('run_section_19', value: true) }

role = input('server_role', value: '').to_s.strip.downcase
  only_if("Not applicable: requires server_role member_server or domain_controller (server_role=#{role})") do
    %w[member_server domain_controller].include?(role)
  end
  tag cis_id: '19.7.8.3'
  describe registry_key('HKEY_USERS\\{{ item }}\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent') do
    its('DisableTailoredExperiencesWithDiagnosticData') { should cmp 1 }
  end
end

control 'cis-19.7.8.4' do
  impact 1.0
  title 'Ensure Turn off all Windows spotlight features is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 19.7.8.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Section 19 controls disabled') { input('run_section_19', value: true) }

role = input('server_role', value: '').to_s.strip.downcase
  only_if("Not applicable: requires server_role member_server or domain_controller (server_role=#{role})") do
    %w[member_server domain_controller].include?(role)
  end
  tag cis_id: '19.7.8.4'
  describe registry_key('HKEY_USERS\\{{ item }}\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent') do
    its('DisableWindowsSpotlightFeatures') { should cmp 1 }
  end
end

control 'cis-19.7.8.5' do
  impact 1.0
  title 'Ensure Turn off Spotlight collection on Desktop is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 19.7.8.5.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Section 19 controls disabled') { input('run_section_19', value: true) }

role = input('server_role', value: '').to_s.strip.downcase
  only_if("Not applicable: requires server_role member_server or domain_controller (server_role=#{role})") do
    %w[member_server domain_controller].include?(role)
  end
  tag cis_id: '19.7.8.5'
  describe registry_key('HKEY_USERS\\{{ item }}\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent') do
    its('DisableSpotlightCollectionOnDesktop') { should cmp 1 }
  end
end

control 'cis-19.7.26.1' do
  impact 1.0
  title 'Ensure Prevent users from sharing files within their profile is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 19.7.26.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Section 19 controls disabled') { input('run_section_19', value: true) }

role = input('server_role', value: '').to_s.strip.downcase
  only_if("Not applicable: requires server_role member_server or domain_controller (server_role=#{role})") do
    %w[member_server domain_controller].include?(role)
  end
  tag cis_id: '19.7.26.1'
  describe registry_key('HKEY_USERS\\{{ item }}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    its('NoInplaceSharing') { should cmp 1 }
  end
end

control 'cis-19.7.44.1' do
  impact 1.0
  title 'Ensure Always install with elevated privileges is set to Disabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 19.7.44.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Section 19 controls disabled') { input('run_section_19', value: true) }

role = input('server_role', value: '').to_s.strip.downcase
  only_if("Not applicable: requires server_role member_server or domain_controller (server_role=#{role})") do
    %w[member_server domain_controller].include?(role)
  end
  tag cis_id: '19.7.44.1'
  describe registry_key('HKEY_USERS\\{{ item }}\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer') do
    its('AlwaysInstallElevated') { should cmp 0 }
  end
end

control 'cis-19.7.46.2.1' do
  impact 1.0
  title 'Ensure Prevent Codec Download is set to Enabled'
  desc  'CIS Microsoft Windows Server 2025 v1.0.0 control 19.7.46.2.1.'
  only_if('Level 2 controls disabled') { input('run_level_2') }
  only_if('Section 19 controls disabled') { input('run_section_19', value: true) }

role = input('server_role', value: '').to_s.strip.downcase
  only_if("Not applicable: requires server_role member_server or domain_controller (server_role=#{role})") do
    %w[member_server domain_controller].include?(role)
  end
  tag cis_id: '19.7.46.2.1'
  describe registry_key('HKEY_USERS\\{{ item }}\\SOFTWARE\\Policies\\Microsoft\\Windowsmediaplayer') do
    its('PreventCodecDownload') { should cmp 1 }
  end
end
