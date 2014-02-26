#!/usr/bin/env ruby

$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'net/tftp+'
require 'optparse'
require 'ostruct'
require 'logger'

LogLevel = Logger::INFO

$tftplog = Logger.new($stderr)
$tftplog.level = LogLevel
$log = $tftplog

def parse_args
    # Set up defaults
    options = OpenStruct.new
    options.root = nil
    options.ip = nil
    options.debug = false
    options.port = 69

    banner =<<EOF
Usage: tftp_server <options>
EOF
    opts = nil
    begin
        $log.debug("server") { "Parsing command line arguments" }
        opts = OptionParser.new do |opts|
            opts.banner = banner

            opts.on('-r', '--root=', 'Directory to serve from') do |r|
                options.root = r
                $log.debug('server') { "root is #{r}" }
            end
            opts.on('-i', '--ip=', 'IP address to bind to (default: 0.0.0.0)') do |i|
                options.host = i
                $log.debug('server') { "ip is #{i}" }
            end
            opts.on('-p', '--port=', 'Local port to use (default: 69)') do |p|
                options.port = p.to_i
                $log.debug('server') { "port is #{p}" }
            end
            opts.on('-d', '--debug', 'Debugging output on') do |d|
                options.debug = d
                $log.level = Logger::DEBUG
                $log.debug('server') { "Debug output requested" }
            end
            opts.on_tail('-h', '--help', 'Show this message') do
                puts opts
                exit
            end
        end.parse!
        
        unless options.port > 0 and options.port < 65537
            raise OptionParser::InvalidOption,
                "port must be positive integer between 1 and 65536"
        end
        # Set defaults.
        options.port = 69           unless options.port
        options.root = '/tftpboot'  unless options.root
        options.ip = ''             unless options.ip
    rescue Exception => details
        $stderr.puts details.to_s
        exit 1
    end

    return options
end

def main
    options = parse_args

    size = 0
    $log.info('server') { "Starting server listening on:" }
    $log.info('server') { "   ip   = #{options.ip.length > 0 ?
                                       options.ip :
                                       'localhost'}" }
    $log.info('server') { "   port = #{options.port}" }
    $log.info('server') { "   root = #{options.root}" }
    $log.info('server') { "Options: #{options}" }

    server = TftpServer.new(options.root)
    server.listen(options.port, options.root, options.ip)
end

main
