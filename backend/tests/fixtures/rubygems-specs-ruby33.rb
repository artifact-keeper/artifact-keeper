# Generator for rubygems-specs-ruby33.4.8.gz: a real `Marshal.dump` of a
# RubyGems specs index, gzipped the way rubygems.org serves specs.4.8.gz.
# The shared "ruby" String and the shared Gem::Version object make Ruby emit
# `@` object links, which the specs decoder must resolve.
#   podman run --rm -v "$PWD":/w:Z docker.io/library/ruby:3.3-slim ruby /w/rubygems-specs-ruby33.rb
require 'rubygems'
require 'zlib'
ruby = "ruby"
v = Gem::Version.new("13.2.1")
specs = [
  ["rake", v, ruby],
  ["rake", v, "java"],
  ["rake", Gem::Version.new("13.0.0"), ruby],
  ["rails", Gem::Version.new("7.1.0"), ruby],
  ["nokogiri", Gem::Version.new("1.16.0"), "x86_64-linux"],
  ["private-gem", Gem::Version.new("9.9.9"), ruby],
]
Zlib::GzipWriter.open("/w/rubygems-specs-ruby33.4.8.gz") { |gz| gz.mtime = 0; gz.write(Marshal.dump(specs)) }
