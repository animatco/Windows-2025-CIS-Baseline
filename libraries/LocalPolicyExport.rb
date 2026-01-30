# frozen_string_literal: true

module LocalPolicyExport

  require 'json'

  #
  # Export local security policy into a structured hash
  #
  def self.export
    raw = inspec.command('secedit /export /cfg C:\\Windows\\Temp\\secpol.cfg').stdout
    parse(raw)
  end

  #
  # Parse secedit output
  #
  def self.parse(text)
    result = {}
    current_section = nil

    text.each_line do |line|
      line = line.strip
      next if line.empty?

      if line.start_with?('[') && line.end_with?(']')
        current_section = line[1..-2]
        result[current_section] ||= {}
        next
      end

      key, value = line.split('=', 2)
      next if key.nil? || value.nil?

      result[current_section][key.strip] = value.strip
    end

    result
  end

end
