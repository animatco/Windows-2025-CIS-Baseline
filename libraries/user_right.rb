class UserRight < Inspec.resource(1)
  name 'user_right'
  desc 'Reads User Rights Assignment (Privilege Rights) via secedit export.'
  supports platform: 'windows'

  WELL_KNOWN_SIDS = {
    'S-1-5-11'       => 'Authenticated Users',
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
    'S-1-5-32-555'   => 'Remote Desktop Users',
    'S-1-5-6'        => 'SERVICE',
    'S-1-5-90-0'     => 'Window Manager\\Window Manager Group'
  }.freeze

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
    WELL_KNOWN_SIDS.fetch(sid, sid)
  end
end
