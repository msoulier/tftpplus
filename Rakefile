require 'rake/testtask'
require 'rake/rdoctask'
require 'rake/clean'
require 'rake/gempackagetask'

Version = '0.3'

task "default" => ["test"]

lib_dir = File.expand_path('lib')
test_dir = File.expand_path('test')

Rake::TestTask.new('test') do |t|
    t.libs = [lib_dir, test_dir]
    t.pattern = 'test/**/*.rb'
    t.warning = true
end

Rake::RDocTask.new('rdoc') do |t|
    t.rdoc_files.include('README', 'lib/**/*.rb')
    t.main = 'README'
    t.title = 'Tftpplus API documentation'
end

task 'tar' do
    system "tar -C .. --exclude '.svn' -zcvf tftpplus-#{Version}.tar.gz tftpplus/{test,doc,lib,bin,ChangeLog,Rakefile,README}"
end

task 'pushsite' do
    system "scp -r site/* msoulier@rubyforge.org:/var/www/gforge-projects/tftpplus"
end

CLEAN.include('pkg', 'html')

spec = Gem::Specification.new do |spec|
    spec.name = 'tftpplus'
    spec.summary = 'A pure tftp implementation with support for variable block sizes'
    spec.description = %{A new tftp library for clients and servers that
    supports RFCs 1350, 2347 and 2348 (ie. variable block sizes). It includes
    a sample client implementation, and will eventually include a
    multi-threaded server as well.}
    spec.author = 'Michael P. Soulier'
    spec.email = 'msoulier@digitaltorque.ca'
    spec.homepage = 'http://tftpplus.rubyforge.org'
    spec.test_files = Dir['test/*.rb']
    spec.executables = ['tftp_client.rb']
    spec.files = FileList['lib/**/*.rb', 'README', 'ChangeLog'] + spec.test_files
    spec.version = Version
end

Rake::GemPackageTask.new(spec) do |pkg|
    pkg.need_zip = false
    pkg.need_tar = false
end
