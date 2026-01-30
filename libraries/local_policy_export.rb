# frozen_string_literal: true

#
# Local Security Policy export parser (secedit + registry fallback)
# Windows Server 2012R2 → 2025 compatible
# WinRM‑safe (no profile temp dirs)
#

class SeceditPolicy
  EXPORT_CFG = 'C:\\Windows\\Temp\\inspec-secpol.cfg'.freeze

  def initialize(inspec)
    @inspec = inspec
    @cache  = nil
  end

  def export_and_parse
    return @cache if @cache

    #
    # Remove stale file (no `.run` — Inspec executes automatically)
    #
    @inspec.command(%(cmd.exe /c del /f /q "#{EXPORT_CFG}" 2>nul))

    #
    # WinRM‑safe secedit export
    #
    cmd = @inspec.command(%(cmd.exe /c secedit /export /cfg "#{EXPORT_CFG}" /areas SECURITYPOLICY USER_RIGHTS /quiet))

    if cmd.exit_status == 0 &&
       @inspec.file(EXPORT_CFG).exist? &&
       @inspec.file(EXPORT_CFG).size > 0

      @cache = parse_ini(@inspec.file(EXPORT_CFG).content)
      return @cache
    end

    #
    # Registry fallback for password/lockout policy
    #
    @cache = {
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
  end

  private

  #
  # INI parser for secedit export
  #
  def parse_ini(text)
    out     = Hash.new { |h, k| h[k] = {} }
    current = nil

    text.to_s.each_line do |line|
      line = line.strip
      next if line.empty? || line.start_with?(';')

      if line.start_with?('[') && line.end_with?(']')
        current = line[1..-2]
        next
      end

      next unless current

      if (idx = line.index('='))
        key = line[0...idx].strip
        val = line[(idx + 1)..].strip
        out[current][key] = val
      end
    end

    out
  end

  #
  # Registry fallback for password/lockout policy
  #
  def registry_policy(key)
    ps = <<~POWERSHELL
      $p = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' -ErrorAction SilentlyContinue
      if ($p -and ($p.PSObject.Properties.Name -contains '#{key}')) {
        $p.#{key}
      }
    POWERSHELL

    # Let Ruby escape the script safely
    cmd = @inspec.command("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command #{ps.inspect}")
    return nil unless cmd.exit_status == 0

    raw = cmd.stdout.to_s.strip
    return nil if raw.empty?

    raw.match?(/^[-]?\d+$/) ? raw.to_i : raw
  end
end

#
# Resource: local_security_policy
#
class LocalSecurityPolicy < Inspec.resource(1)
  name 'local_security_policy'
  desc 'Reads Local Security Policy values via secedit export or registry fallback.'
  supports platform: 'windows'

  def initialize
    super()
    @policy = SeceditPolicy.new(inspec).export_and_parse || {}
  end

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

  #
  # Dynamic section scanning (future‑proof)
  #
  def lookup_key(key)
    return nil unless @policy.is_a?(Hash)

    @policy.each_value do |section|
      next unless section.is_a?(Hash)
      return section[key] if section.key?(key)
    end

    nil
  end

  def to_typed(v)
    return nil if v.nil?
    s = v.to_s.strip
    s.match?(/^[-]?\d+$/) ? s.to_i : s
  end
end

#
# Resource: user_right('SeXxxPrivilege')
#
class UserRight < Inspec.resource(1)
  name 'user_right'
  desc 'Reads User Rights Assignment (Privilege Rights) via secedit export.'
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

    rights = @policy['Privilege Rights']
    return [] unless rights.is_a?(Hash)

    raw = rights[@right]
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

  def ==(other)
    value == other
  end

  def include?(item)
    value.include?(item)
  end
end
