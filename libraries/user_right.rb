# frozen_string_literal: true

class UserRight < Inspec.resource(1)
  name 'user_right'
  desc 'Reads User Rights Assignment (Privilege Rights) via secedit export with SID resolution.'
  supports platform: 'windows'

  WELL_KNOWN_SIDS = {
    'S-1-0-0'        => 'Null Authority',
    'S-1-1-0'        => 'Everyone',
    'S-1-2-0'        => 'Local',
    'S-1-2-1'        => 'Console Logon',
    'S-1-3-0'        => 'Creator Owner',
    'S-1-3-1'        => 'Creator Group',
    'S-1-3-4'        => 'Owner Rights',
    'S-1-5-1'        => 'Dialup',
    'S-1-5-2'        => 'Network',
    'S-1-5-3'        => 'Batch',
    'S-1-5-4'        => 'Interactive',
    'S-1-5-6'        => 'SERVICE',
    'S-1-5-7'        => 'Anonymous',
    'S-1-5-8'        => 'Proxy',
    'S-1-5-9'        => 'Enterprise Domain Controllers',
    'S-1-5-10'       => 'Self',
    'S-1-5-11'       => 'Authenticated Users',
    'S-1-5-12'       => 'Restricted Code',
    'S-1-5-13'       => 'Terminal Server User',
    'S-1-5-14'       => 'Remote Interactive Logon',
    'S-1-5-15'       => 'This Organization',
    'S-1-5-17'       => 'IUSR (Internet Information Services User)',
    'S-1-5-18'       => 'SYSTEM',
    'S-1-5-19'       => 'LOCAL SERVICE',
    'S-1-5-20'       => 'NETWORK SERVICE',
    'S-1-5-32-544'   => 'Administrators',
    'S-1-5-32-545'   => 'Users',
    'S-1-5-32-546'   => 'Guests',
    'S-1-5-32-547'   => 'Power Users',
    'S-1-5-32-548'   => 'Account Operators',
    'S-1-5-32-549'   => 'Server Operators',
    'S-1-5-32-550'   => 'Print Operators',
    'S-1-5-32-551'   => 'Backup Operators',
    'S-1-5-32-552'   => 'Replicator',
    'S-1-5-32-555'   => 'Remote Desktop Users',
    'S-1-5-32-556'   => 'Network Configuration Operators',
    'S-1-5-32-557'   => 'Incoming Forest Trust Builders',
    'S-1-5-32-558'   => 'Performance Monitor Users',
    'S-1-5-32-559'   => 'Performance Log Users',
    'S-1-5-32-560'   => 'Windows Authorization Access Group',
    'S-1-5-32-561'   => 'Terminal Server License Servers',
    'S-1-5-32-562'   => 'Distributed COM Users',
    'S-1-5-32-568'   => 'IIS_IUSRS',
    'S-1-5-32-569'   => 'Cryptographic Operators',
    'S-1-5-32-573'   => 'Event Log Readers',
    'S-1-5-32-574'   => 'Certificate Service DCOM Access',
    'S-1-5-32-575'   => 'RDS Remote Access Servers',
    'S-1-5-32-576'   => 'RDS Endpoint Servers',
    'S-1-5-32-577'   => 'RDS Management Servers',
    'S-1-5-32-578'   => 'Hyper-V Administrators',
    'S-1-5-32-579'   => 'Access Control Assistance Operators',
    'S-1-5-32-580'   => 'Remote Management Users',
    'S-1-5-80-0'     => 'NT SERVICE\\ALL SERVICES',
    'S-1-5-90-0'     => 'Window Manager\\Window Manager Group',
    'S-1-5-113'      => 'Local Account',
    'S-1-5-114'      => 'Local Account and Member of Administrators Group',
    'S-1-5-NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS' => 'ENTERPRISE DOMAIN CONTROLLERS'
  }.freeze

  def initialize(right_name)
    super()
    @right  = right_name.to_s
    @policy = SeceditPolicy.new(inspec).export_and_parse || {}
    @sid_cache = {}
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
       .map { |sid| resolve_sid(sid) }
       .reject(&:empty?)
  end

  def values
    value
  end

  def include?(item)
    value.include?(item)
  end

  def ==(other)
    value == other
  end

  private

  def resolve_sid(sid)
    return nil if sid.nil? || sid.empty?

    # Check static well-known SIDs first
    return WELL_KNOWN_SIDS[sid] if WELL_KNOWN_SIDS.key?(sid)

    # Check cache for domain-specific SIDs
    return @sid_cache[sid] if @sid_cache.key?(sid)

    # Try to resolve domain-specific SID via PowerShell
    resolved = resolve_domain_sid(sid)
    @sid_cache[sid] = resolved
    resolved
  end

  def resolve_domain_sid(sid)
    ps = <<~POWERSHELL
      try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier('#{sid}')
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        $objUser.Value
      } catch {
        '#{sid}'
      }
    POWERSHELL

    cmd = inspec.command("powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command #{ps.inspect}")
    return sid unless cmd.exit_status == 0

    result = cmd.stdout.to_s.strip
    result.empty? ? sid : result
  end
end

# Ensure controls can always resolve the constant, regardless of InSpec load context.
Object.const_set(:UserRight, UserRight) unless Object.const_defined?(:UserRight)
 