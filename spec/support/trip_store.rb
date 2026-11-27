# frozen_string_literal: true

# What a site would pass a trip as `store:` (Rails.cache), as small as it can be.
class TripStore
  attr_reader :entries

  def initialize = @entries = {}
  def read(key) = @entries[key]
  def write(key, value, expires_in:) = (@entries[key] = value) && expires_in
  def delete(key) = @entries.delete(key)
end
