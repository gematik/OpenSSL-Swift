source "https://rubygems.org"

ruby "4.0.6"

gem "fastlane", "~>2.220"
gem "jazzy", "~>0.14"

plugins_path = File.join(File.dirname(__FILE__), 'fastlane', 'Pluginfile')
eval_gemfile(plugins_path) if File.exist?(plugins_path)
