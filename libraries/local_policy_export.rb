# frozen_string_literal: true

# Local Security Policy export parser (secedit + registry fallback)
#
# Exposes:
#   local_security_policy.PasswordHistorySize
#   local_security_policy['MinimumPasswordLength']
#   user_right('SeDenyNetworkLogonRight')
#
# Notes:
# - Uses a fixed, WinRM‑safe export path in C:\Windows\Temp
# - Falls back to Netlogon\Parameters registry for core password/lockout policies
# - Avoids brittle section name assumptions by scanning all sections
# - Requires local admin

class SeceditPolicy
  EXPORT_CFG_PATH = 'C:\\Windows\\Temp\\inspec-secpol.cfg').freeze

  def initialize(inspec)
    @inspec = inspec
    @cache  = nil
  end

  def export_and_parse
    return @cache if @cache

    # Best effort: remove any stale file first
    @inspec.command(%(cmd.exe /c del /f /q "#{EXPORT_CFG_PATH}" 2>nul)).run

    # Single, explicit export attempt (WinRM‑friendly)
    cmd = @inspec.command(%(cmd.exe /c secedit /export /cfg "#{EXPORT_CFG_PATH}" /areas SECURITYPOLICY USER_RIGHTS /quiet))

    if cmd.exit_status == 0 && @inspec.file(EXPORT_CFG_PATH).exist? && @inspec.file(EXPORT_CFG_PATH).size > 0
      @cache = parse_ini(@inspec.file(EXPORT_CFG_PATH).content)
      return @cache
    end

    # Registry fallback for core password/lockout policies
    fallback = {
      'System Access' => {
        'PasswordHistorySize'       => registry_policy('PasswordHistorySize'),
        'MaximumPasswordAge'        => registry_policy('MaximumPasswordAge'),
        'MinimumPasswordAge'        => registry_policy('MinimumPasswordAge'),
        'MinimumPasswordLength'     => registry_policy('MinimumPasswordLength'),
        'PasswordComplexity'        => registry_policy('PasswordComplexity'),
        'LockoutBadCount'           => registry_policy('LockoutBadCount'),
        'ResetLockoutCount'         => registry_policy('ResetLockoutCount'),
        'LockoutDuration'           => registry_policy('LockoutDuration'),
        'AllowAdministratorLockout' => registry_policy('AllowAdministratorLockout'),
        'ClearTextPassword'         => registry_policy('ClearTextPassword')
      }
    }

    @cache = fallback
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

  # Registry fallback for password/lockout policy
  #
  # Most of these live under:
  #   HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
  #
  # Note: MaximumPasswordAge is stored in seconds.
  def registry_policy(key)
    ps = <<~POWERSHELL
      $p = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' -ErrorAction SilentlyContinue
      if ($p -and ($p.PSObject.Properties.Name -contains '#{key}')) {
        $p.#{key}
      }
    POWERSHELL

    cmd = @inspec.command(%(powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "#{ps.gsub("\n", ' ')}"))
    return nil unless cmd.exit_status == 0

    raw = cmd.stdout.to_s.strip
    return nil if raw.empty?

    # Convert to integer when possible
    if raw.match?(/^[-]?\d+$/)
      raw.to_i
    else
      raw
    end
  end
end

# Resource: local_security_policy
class LocalSecurityPolicy < Inspec.resource(1)
  name 'local_security_policy'
  desc 'Reads Local Security Policy values via secedit export or registry fallback.'
  supports platform: 'windows'

  def initialize
    super()
    @policy = SeceditPolicy.new(inspec).export_and_parse || {}
  end

  # Allow: its('PasswordHistorySize') { should cmp 24 }
  def method_missing(name, *args)
    key   = name.to_s
    value = lookup_key(key)
    return to_typed(value) unless value.nil?

    super
  end

  def respond_to_missing?(name, include_private = false)
    !lookup_key(name.to_s).nil? || super
  end

  def [](key)
    to_typed(lookup_key(key.to_s))
  end

  private

  # Scan all sections for the key instead of assuming fixed section names
  def lookup_key(key)
    return nil unless @policy.is_a?(Hash)

    @policy.each_value do |section_hash|
      next unless section_hash.is_a?(Hash)
      return section_hash[key] if section_hash.key?(key)
    end

    nil
  end

  def to_typed(v)
    return nil if v.nil?
    s = v.to_s.strip
    return s.to_i if s.match?(/^[-]?\d+$/)
    s
  end
end

# Resource: user_right('SeXxxPrivilege') -> Array[String]
class UserRight < Inspec.resource(1)
  name 'user_right'
  desc 'Reads User Rights Assignment (Privilege Rights) via secedit export or registry fallback.'
  supports platform: 'windows'

  def initialize(right_name)
    super()
    @right  = right_name.to_s
    @policy = SeceditPolicy.new(inspec).export_and_parse || {}
  end

  def to_s
    "User Right #{@right}"
  end

  def value
    return [] unless @policy.is_a?(Hash)

    priv_rights = @policy['Privilege Rights']
    return [] unless priv_rights.is_a?(Hash)

    raw = priv_rights[@right]
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
