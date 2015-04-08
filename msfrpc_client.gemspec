$LOAD_PATH.push File.expand_path('../lib', __FILE__)
require 'msfrpc_client/version'

Gem::Specification.new do |s|
  s.name        = 'msfrpc_client'
  s.version     = Msfrpc::Client::VERSION
  s.authors     = [
    'Maxim Zhukov',
    'HD Moore'
  ]

  s.email       = [
    'crmaxx@gmail.com',
    'hdm@rapid7.com'
  ]

  s.homepage    = "http://www.metasploit.com/"
  s.summary     = "Ruby API client for the Rapid7 Metasploit Pro RPC service"
  s.description = %(
   This gem provides a Ruby API client to access the Rapid7 Metasploit Pro RPC service.
  ).gsub(/\s+/, ' ').strip

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  s.require_paths = ['lib']
  s.licenses      = ['BSD-2-Clause']

  s.add_runtime_dependency 'msgpack', '~> 0.5.8', '>= 0.5.8'
  s.add_runtime_dependency 'librex', '~> 0.0.70', '>= 0.0.70'
end
