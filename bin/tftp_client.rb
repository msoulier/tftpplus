#!/usr/bin/env ruby

$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'net/tftp+'
require 'optparse'
require 'ostruct'

def parse_args
    # Set up defaults
    options = OpenStruct.new
    options.filename = nil
    options.host = nil
    options.verbose = false
    options.blksize = 512
    options.port = 69

    banner =<<EOF
Usage: tftp_client <options>
EOF
    opts = nil
    begin
        opts = OptionParser.new do |opts|
            opts.banner = banner

            opts.on('-f', '--filename=MANDATORY', 'Remote filename') do |f|
                options.filename = f
            end
            opts.on('-h', '--host=MANDATORY', 'Remote host or IP address') do |h|
                options.host = h
            end
            opts.on('-p', '--port=', 'Remote port to use (default: 69)') do |p|
                options.port = p.to_i
            end
            opts.on('-v', '--verbose', 'Verbose debugging output') do |d|
                options.verbose = d
            end
            opts.on('-b', '--blksize=', 'Blocksize option: 8-65536 bytes') do |b|
                options.blksize = b.to_i
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
    puts "Starting download of #{options.filename} from #{options.host}"
    puts "Options: blksize = #{options.blksize}"

    client = TftpClient.new(options.host, options.port)
    tftp_opts = { :blksize => options.blksize.to_i }
    client.download(options.filename, options.filename, tftp_opts) do |pkt|
        size += pkt.data.length
        puts "Downloaded #{size} bytes" if options.verbose
    end

    finish = Time.now
    duration = finish - start

    puts ""
    puts "Started: #{start}"
    puts "Finished: #{finish}"
    puts "Duration: #{duration}"
    puts "Downloaded #{size} bytes in #{duration} seconds"
    puts "Throughput: #{(size/duration)*8} bps"
    puts "            #{(size/duration)*8 / 1024} kbps"
end

main
