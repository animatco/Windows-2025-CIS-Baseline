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
    return sid unless sid.start_with?('S-1-')

    ps = <<~POWERSHELL
      try {
        $obj = New-Object System.Security.Principal.SecurityIdentifier("#{sid}")
        $obj.Translate([System.Security.Principal.NTAccount]).Value
      } catch {
        "#{sid}"
      }
    POWERSHELL

    cmd = inspec.command("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command #{ps.inspect}")
    out = cmd.stdout.to_s.strip
    out.empty? ? sid : out
  end
end
