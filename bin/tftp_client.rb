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
    options.filename = nil
    options.host = nil
    options.debug = false
    options.blksize = 512
    options.port = 69

    banner =<<EOF
Usage: tftp_client <options>
EOF
    opts = nil
    begin
        $log.debug("client") { "Parsing command line arguments" }
        opts = OptionParser.new do |opts|
            opts.banner = banner

            opts.on('-f', '--filename=MANDATORY', 'Remote filename') do |f|
                options.filename = f
                $log.debug('client') { "filename is #{f}" }
            end
            opts.on('-h', '--host=MANDATORY', 'Remote host or IP address') do |h|
                options.host = h
                $log.debug('client') { "host is #{h}" }
            end
            opts.on('-p', '--port=', 'Remote port to use (default: 69)') do |p|
                options.port = p.to_i
                $log.debug('client') { "port is #{p}" }
            end
            opts.on('-d', '--debug', 'Debugging output on') do |d|
                options.debug = d
                $log.level = Logger::DEBUG
                $log.debug('client') { "Debug output requested" }
            end
            opts.on('-b', '--blksize=', 'Blocksize option: 8-65536 bytes') do |b|
                options.blksize = b.to_i
                $log.debug('client') { "blksize is #{b}" }
            end
            opts.on_tail('-h', '--help', 'Show this message') do
                puts opts
                exit
            end
        end.parse!
        
        unless options.filename and options.host
            raise OptionParser::InvalidOption,
                "Both --host and --filename are required"
        end
        #unless options.blksize =~ /^\d+/
        #    raise OptionParser::InvalidOption,
        #        "blksize must be an integer"
        #end
        unless options.blksize >= 8 and options.blksize <= 65536
            raise OptionParser::InvalidOption,
                "blksize can only be between 8 and 65536 bytes"
        end
        unless options.port > 0 and options.port < 65537
            raise OptionParser::InvalidOption,
                "port must be positive integer between 1 and 65536"
        end
    rescue Exception => details
        $stderr.puts details.to_s
        $stderr.puts opts
        exit 1
    end

    return options
end

def main
    options = parse_args

    size = 0
    start = Time.now
    $log.info('client') { "Starting download of #{options.filename} from #{options.host}" }
    $log.info('client') { "Options: blksize = #{options.blksize}" }

    client = TftpClient.new(options.host, options.port)
    tftp_opts = { :blksize => options.blksize.to_i }
    client.download(options.filename, options.filename, tftp_opts) do |pkt|
        size += pkt.data.length
        $log.debug('client') { "Downloaded #{size} bytes" }
    end

    finish = Time.now
    duration = finish - start

    $log.info('client') { "" }
    $log.info('client') { "Started: #{start}" }
    $log.info('client') { "Finished: #{finish}" }
    $log.info('client') { "Duration: #{duration}" }
    $log.info('client') { "Downloaded #{size} bytes in #{duration} seconds" }
    $log.info('client') { "Throughput: #{(size/duration)*8} bps" }
    $log.info('client') { "            #{(size/duration)*8 / 1024} kbps" }
end

main
