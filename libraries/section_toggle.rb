module SectionToggle
  def section_enabled?(section)
    input("run_section_#{section}", value: true)
  end
end

# Ensure controls can always resolve constants, regardless of InSpec load context.
if defined?(Object) && defined?(self)
  constants.each do |c|
    next if Object.const_defined?(c)
    Object.const_set(c, const_get(c))
  end
end

