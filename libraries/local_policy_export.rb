# frozen_string_literal: true

# Local Security Policy export parser (secedit + WMI fallback)
#
# Exposes:
#   local_security_policy.PasswordHistorySize
#   local_security_policy['MinimumPasswordLength']
#   user_right('SeDenyNetworkLogonRight')
#
# Notes:
# - Tries secedit export (interactive + WinRM‑friendly)
# - Falls back to WMI/registry for core CIS 1.1.x/1.2.x values
# - Requires local admin

require 'tmpdir'

class SeceditPolicy
  def initialize(inspec)
    @inspec = inspec
    @cache  = nil
  end

  def export_and_parse
    return @cache if @cache

    dir = Dir.mktmpdir('inspec-secedit-')
    cfg = File.join(dir, 'secpol.cfg')

    # Try basic export (matches interactive)
    cmd = @inspec.command(%(cmd.exe /c secedit /export /cfg "#{cfg}" /quiet))
    return parse_ini(@inspec.file(cfg).content) if cmd.exit_status == 0

    # Try explicit areas (WinRM‑friendly)
    cmd = @inspec.command(%(cmd.exe /c secedit /export /cfg "#{cfg}" /areas SECURITYPOLICY USER_RIGHTS /quiet))
    return parse_ini(@inspec.file(cfg).content) if cmd.exit_status == 0

    # WMI fallback for core CIS password/lockout policies
    @inspec.stderr.puts "secedit export failed (both attempts), using WMI fallback"
    @inspec.stderr.puts "secedit stderr: #{cmd.stderr}"

    fallback = {
      'System Access' => {
        'PasswordHistorySize'     => wmi_policy('PasswordHistorySize'),
        'MaximumPasswordAge'      => wmi_policy('MaximumPasswordAge'),
        'MinimumPasswordAge'      => wmi_policy('MinimumPasswordAge'),
        'MinimumPasswordLength'   => wmi_policy('MinimumPasswordLength'),
        'PasswordComplexity'      => wmi_policy('PasswordComplexity'),
        'LockoutBadCount'         => wmi_policy('LockoutBadCount'),
        'ResetLockoutCount'       => wmi_policy('ResetLockoutCount'),
        'LockoutDuration'         => wmi_policy('LockoutDuration'),
        'AllowAdministratorLockout' => wmi_policy('AllowAdministratorLockout'),
        'ClearTextPassword'       => wmi_policy('ClearTextPassword')
      }
    }

    @cache = fallback
    @cache
  ensure
    begin
      if dir && dir.start_with?(Dir.tmpdir)
        @inspec.command(%(cmd.exe /c rmdir /s /q "#{dir}")).run
      end
    rescue StandardError
      # best effort cleanup
    end
  end

  private

  def parse_ini(text)
    out     = Hash.new { |h, k| h[k] = {} }
    current = nil

    text.to_s.each_line do |line|
      line = line.strip
      next if line.empty?
      next if line.start_with?(';')

      if line.start_with?('[') && line.end_with?(']')
        current = line[1..-2]
        next
      end

      next unless current

      if (idx = line.index('='))
        k = line[0...idx].strip
        v = line[(idx + 1)..].strip
        out[current][k] = v
      end
    end

    out
  end

  def wmi_policy(key)
    cmd = @inspec.command(%(powershell.exe -c "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name '#{key}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty #{key}"))
    return cmd.stdout.strip.to_i if cmd.exit_status == 0 && !cmd.stdout.strip.empty?
    nil
  end
end

# Resource: local_security_policy
class LocalSecurityPolicy < Inspec.resource(1)
  name 'local_security_policy'
  desc 'Reads Local Security Policy values via secedit export or WMI fallback.'
  supports platform: 'windows'

  def initialize
    super()
    @policy = SeceditPolicy.new(inspec).export_and_parse
  end

  # Allow: its('PasswordHistorySize') { should cmp 24 }
  def method_missing(name, *args)
    key   = name.to_s
    value = lookup_key(key)
    return to_typed(value) if value

    super
  end

  def respond_to_missing?(name, include_private = false)
    !!lookup_key(name.to_s) || super
  end

  def [](key)
    to_typed(lookup_key(key))
  end

  private

  def lookup_key(key)
    %w[System Access Event Audit Registry Values].each do |section|
      return @policy[section][key] if @policy[section].key?(key)
    end
    nil
  end

  def to_typed(v)
    return nil if v.nil?
    # secedit/WMI often stores numbers as strings
    return v.to_i if v.match?(/^[-]?\d+$/)
    v
  end
end

# Resource: user_right('SeXxxPrivilege') -> Array[String]
class UserRight < Inspec.resource(1)
  name 'user_right'
  desc 'Reads User Rights Assignment (Privilege Rights) via secedit export.'
  supports platform: 'windows'

  def initialize(right_name)
    super()
    @right  = right_name.to_s
    @policy = SeceditPolicy.new(inspec).export_and_parse
  end

  def to_s
    "User Right #{@right}"
  end

  def value
    raw = @policy['Privilege Rights'] && @policy['Privilege Rights'][@right]
    return [] if raw.nil? || raw.strip.empty?

    raw.split(',').map { |s| s.strip.sub(/^\*/, '') }.reject(&:empty?)
  end

  def method_missing(name, *args)
    return value if name.to_s == 'values'
    super
  end

  def respond_to_missing?(name, include_private = false)
    name.to_s == 'values' || super
  end

  # Allow RSpec expectations directly:
  #   describe user_right('SeDenyNetworkLogonRight') { it { should include 'Guests' } }
  def ==(other)
    value == other
  end

  def include?(item)
    value.include?(item)
  end
end
