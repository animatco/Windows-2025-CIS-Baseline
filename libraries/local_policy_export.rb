# frozen_string_literal: true

# Local Security Policy export parser (secedit)
#
# Exposes:
#   local_security_policy.PasswordHistorySize
#   user_right('SeDenyNetworkLogonRight')
#
# Notes:
# - Uses secedit export; requires local admin.
# - Caches exported policy in a temp file per-run.

require 'tmpdir'

class SeceditPolicy
  def initialize(inspec)
    @inspec = inspec
    @cache = nil
  end

  def export_and_parse
    return @cache if @cache

    dir = Dir.mktmpdir('inspec-secedit-')
    cfg = File.join(dir, 'secpol.cfg')

    cmd = @inspec.command(%(cmd.exe /c secedit /export /cfg "#{cfg}" /quiet))
    raise "secedit export failed: #{cmd.stderr}" unless cmd.exit_status == 0

    text = @inspec.file(cfg).content
    @cache = parse_ini(text)
    @cache
  ensure
    begin
      @inspec.command(%(cmd.exe /c rmdir /s /q "#{dir}")).run if dir && dir.start_with?(Dir.tmpdir)
    rescue StandardError
      # best effort cleanup
    end
  end

  def parse_ini(text)
    out = Hash.new { |h, k| h[k] = {} }
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
end

# Resource: local_security_policy
class LocalSecurityPolicy < Inspec.resource(1)
  name 'local_security_policy'
  desc 'Reads Local Security Policy values via secedit export.'
  supports platform: 'windows'

  def initialize
    super()
    @policy = SeceditPolicy.new(inspec).export_and_parse
  end

  # Allow: its('PasswordHistorySize') { should cmp 24 }
  def method_missing(name, *args)
    key = name.to_s
    # System Access, Event Audit, Registry Values
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
    # secedit often stores numbers as strings
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
    @right = right_name.to_s
    @policy = SeceditPolicy.new(inspec).export_and_parse
  end

  def to_s
    "User Right #{@right}"
  end

  def value
    raw = @policy['Privilege Rights'][@right]
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

  # Allow RSpec expectations directly on the resource:
  #   describe user_right('SeX') { it { should include 'Guests' } }
  def ==(other)
    value == other
  end

  def include?(item)
    value.include?(item)
  end
end
