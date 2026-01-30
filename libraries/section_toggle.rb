module SectionToggle
  def section_enabled?(section)
    input("run_section_#{section}", value: true)
  end
end

Inspec::DSL.include(SectionToggle)
