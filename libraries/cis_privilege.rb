# frozen_string_literal: true

module CisPrivilege

  #
  # Normalize a privilege right array into clean strings
  #
  def self.normalize(list)
    return [] if list.nil?
    Array(list).map(&:to_s).map(&:strip).map(&:upcase)
  end

  #
  # Check if a privilege right includes all expected principals
  #
  def self.includes?(actual_list, expected)
    actual = normalize(actual_list)
    exp    = normalize(expected)
    exp.all? { |e| actual.include?(e) }
  end

  #
  # Check if privilege right is exactly empty (No One)
  #
  def self.empty?(actual_list)
    normalize(actual_list).empty?
  end

end

# Ensure controls can always resolve constants, regardless of InSpec load context.
if defined?(Object) && defined?(self)
  constants.each do |c|
    next if Object.const_defined?(c)
    Object.const_set(c, const_get(c))
  end
end

