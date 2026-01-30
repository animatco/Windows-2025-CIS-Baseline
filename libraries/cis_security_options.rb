# frozen_string_literal: true

module CisSecurityOptions

  #
  # Normalize a value to boolean true/false
  #
  def self.to_bool(value)
    return false if value.nil?
    v = value.to_s.strip
    return true  if v == '1' || v.casecmp('enabled').zero?
    return false if v == '0' || v.casecmp('disabled').zero?
    false
  end

  #
  # Check if a setting is enabled
  #
  def self.enabled?(value)
    to_bool(value) == true
  end

  #
  # Check if a setting is disabled
  #
  def self.disabled?(value)
    to_bool(value) == false
  end

end
