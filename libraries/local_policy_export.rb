# frozen_string_literal: true

#
# Local Security Policy export parser
# - Uses secedit for SECURITYPOLICY + USER_RIGHTS
# - Falls back to registry for System Access + Security Options
# - Windows Server 2012R2 → 2025 compatible
# - WinRM‑safe (no profile temp dirs)
#

class SeceditPolicy
  EXPORT_CFG = 'C:\\Windows\\Temp\\inspec-secpol.cfg'.freeze

  def initialize(inspec)
    @inspec = inspec
    @cache  = nil
  end

  #
  # Main entry point
  #
  def export_and_parse
    return @cache if @cache

    cleanup_stale_export
    run_secedit_export

    if export_successful?
      @cache = parse_ini(read_export_file)
      return @cache
    end

    #
    # Registry fallback (System Access + Security Options)
    #
    @cache = {
      'System Access'     => registry_system_access,
      'Privilege Rights'  => {}, # cannot be reliably reconstructed from registry
      'Security Options'  => registry_security_options
    }

    @cache
  end

  private

  #
  # Remove stale export file
  #
  def cleanup_stale_export
    @inspec.command(%(cmd.exe /c del /f /q "#{EXPORT_CFG}" 2>nul))
  end

  #
  # Execute secedit export
  #
  def run_secedit_export
    @inspec.command(%(cmd.exe /c secedit /export /cfg "#{EXPORT_CFG}" /areas SECURITYPOLICY USER_RIGHTS /quiet))
  end

  #
  # Check if export succeeded
  #
  def export_successful?
    @inspec.file(EXPORT_CFG).exist? &&
      @inspec.file(EXPORT_CFG).size > 0
  end

  #
  # Read exported file content
  #
  def read_export_file
    @inspec.file(EXPORT_CFG).content.to_s
  end

  #
  # INI parser
  #
  def parse_ini(text)
    out     = Hash.new { |h, k| h[k] = {} }
    current = nil

    text.encode!('UTF-8', invalid: :replace, undef: :replace, replace: '')
    text.each_line do |line|
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
  # Registry fallback: System Access
  #
  def registry_system_access
    keys = %w[
      PasswordHistorySize
      MaximumPasswordAge
      MinimumPasswordAge
      MinimumPasswordLength
      PasswordComplexity
      LockoutBadCount
      ResetLockoutCount
      LockoutDuration
      AllowAdministratorLockout
      ClearTextPassword
    ]

    keys.each_with_object({}) do |k, h|
      h[k] = registry_read(
        'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
        k
      )
    end
  end

  #
  # Registry fallback: Security Options
  #
  def registry_security_options
    {
      'EnableAdminAccount'                => registry_read('HKLM:\\SAM\\SAM\\Domains\\Account\\Users\\000001F4', 'F'),
      'EnableGuestAccount'                => registry_read('HKLM:\\SAM\\SAM\\Domains\\Account\\Users\\000001F5', 'F'),
      'LimitBlankPasswordUse'             => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa', 'LimitBlankPasswordUse'),
      'SCENoApplyLegacyAuditPolicy'       => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa', 'SCENoApplyLegacyAuditPolicy'),
      'AddPrinterDrivers'                 => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers', 'AddPrinterDrivers'),
      'RequireSignOrSeal'                 => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters', 'RequireSignOrSeal'),
      'SealSecureChannel'                 => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters', 'SealSecureChannel'),
      'SignSecureChannel'                 => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters', 'SignSecureChannel'),
      'RequireStrongKey'                  => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters', 'RequireStrongKey'),
      'DisableCAD'                        => registry_read('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'DisableCAD'),
      'InactivityTimeoutSecs'             => registry_read('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'InactivityTimeoutSecs'),
      'RequireSecuritySignature'          => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters', 'RequireSecuritySignature'),
      'EnableSecuritySignature'           => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters', 'EnableSecuritySignature')
    }
  end

  #
  # Registry reader (typed)
  #
  def registry_read(path, key)
    ps = <<~POWERSHELL
      $p = Get-ItemProperty -Path '#{path}' -ErrorAction SilentlyContinue
      if ($p -and ($p.PSObject.Properties.Name -contains '#{key}')) {
        $p.#{key}
      }
    POWERSHELL

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
  # Dynamic section scanning
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

    raw.split(',')
       .map { |s| s.strip.sub(/^\*/, '') }
       .reject(&:empty?)
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
