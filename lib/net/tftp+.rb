# A Ruby library for Trivial File Transfer Protocol.
# Supports the following RFCs
# RFC 1350 - THE TFTP PROTOCOL (REVISION 2)
# RFC 2347 - TFTP Option Extension
# RFC 2348 - TFTP Blocksize Option
# Currently, the TftpServer class is not functional.
# The TftpClient class works fine. Let me know if this is not true.

require 'socket'
require 'timeout'
require 'resolv'

# Todo
# - properly handle decoding of options ala rfc 2347
# - use maxdups
# - use socket timeouts
# - implement variable block-sizes

MinBlkSize      = 8
DefBlkSize      = 512
MaxBlkSize      = 65536
SockTimeout     = 5
MaxDups         = 20
Assertions      = true
MaxRetry        = 5

# This class is a Nil logging device. It catches all of the logger calls and
# does nothing with them. It is up to the client to provide a real logger
# and assign it to $tftplog.
class TftpNilLogger
    def method_missing(*args)
        # do nothing
    end
end

# This global is the logger used by the library. By default it is an instance
# of TftpNilLogger, which does nothing. Replace it with a logger if you want
# one.
$tftplog = TftpNilLogger.new

class TftpError < RuntimeError
end

# This function is a custom assertion in the library to catch unsupported
# states and types. If the assertion fails, msg is raised in a TftpError
# exception.
def tftpassert(msg, &code)
    if not code.call and Assertions
        raise TftpError, "Assertion Failed: #{msg}", caller
    end
end

# This class is the root of all TftpPacket classes in the library. It should
# not be instantiated directly. It exists to provide code sharing to the child
# classes.
class TftpPacket
    attr_accessor :opcode, :buffer

    # Class constructor. This class and its children take no parameters. A
    # client is expected to set instance variables after instantiation.
    def initialize
        @opcode = 0
        @buffer = nil
        @options = {}
    end

    # Abstract method, must be implemented in all child classes.
    def encode
        raise NotImplementedError
    end

    # Abstract method, must be implemented in all child classes.
    def decode
        raise NotImplementedError
    end

    # This is a setter for the options hash. It ensures that the keys are
    # Symbols and that the values are strings. You can pass in a non-String
    # value as long as the .to_s method returns a good value.
    def options=(opts)
        myopts = {}
        opts.each do |key, val|
            $tftplog.debug('tftp+') { "looping on key #{key}, val #{val}" }
            $tftplog.debug('tftp+') { "class of key is #{key.class}" }
            tftpassert("options keys must be symbols") { key.class == Symbol }
            myopts[key.to_s] = val.to_s
        end
        @options = myopts
    end

    # A getter for the options hash.
    def options
        return @options
    end

    protected

    # This method takes the portion of the buffer containing the options and
    # decodes it, returning a hash of the option name/value pairs, with the
    # keys as Symbols and the values as Strings.
    def decode_options(buffer)
        # We need to variably decode the buffer. The buffer here is only that
        # part of the original buffer containing options. We will decode the
        # options here and return an options array.
        nulls = 0
        format = ""
        # Count the nulls in the buffer, each one terminates a string.
        buffer.collect do |c|
            if c.to_i == 0
                format += "Z*Z*"
            end
        end
        struct = buffer.unpack(format)

        unless struct.length % 2 == 0
            raise TftpError, "packet with odd number of option/value pairs"
        end

        while not struct.empty?
            name  = struct.shift
            value = struct.shift
            options[name.to_sym] = value
            $tftplog.debug('tftp+') { "decoded option #{name} with value #{value}" }
        end
        return options
    end
end

# This class is a parent class for the RRQ and WRQ packets, as they share a
# lot of code.
#         2 bytes    string   1 byte     string   1 byte
#         -----------------------------------------------
#  RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
#  WRQ    -----------------------------------------------
#      +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
#      |  opc  |filename| 0 |  mode  | 0 | blksize| 0 | #octets| 0 |
#      +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
class TftpPacketInitial < TftpPacket
    attr_accessor :filename, :mode

    def initialize
        super()
        @filename = nil
        @mode = nil
    end

    # Encode of the packet based on the instance variables. Both the filename
    # and mode instance variables must be set or an exception will be thrown.
    def encode
        unless @opcode and @filename and @mode
            raise ArgumentError, "Required arguments missing."
        end

        datalist = []

        format = "n"
        format += "a#{@filename.length}x"
        datalist.push @opcode
        datalist.push @filename

        case @mode
        when "octet"
            format += "a5"
        else
            raise ArgumentError, "Unsupported mode: #{kwargs[:mode]}"
        end
        datalist.push @mode

        format += "x"

        @options.each do |key, value|
            format += "a#{key.length}x"
            format += "a#{value.length}x"
            datalist.push key
            datalist.push value
        end

        @buffer = datalist.pack(format)
        return self
    end

    # Decode the packet based on the contents of the buffer instance variable.
    # It populates the filename and mode instance variables.
    def decode
        unless @buffer
            raise ArgumentError, "Can't decode, buffer is empty."
        end
        struct = @buffer.unpack("nZ*Z*")
        unless struct[0] == 1 or struct[0] == 2
            raise TftpError, "opcode #{struct[0]} is not a RRQ or WRQ!"
        end
        @filename = struct[1]
        unless @filename.length > 0
            raise TftpError, "filename is the null string"
        end
        @mode = struct[2]
        unless valid_mode? @mode
            raise TftpError, "mode #{@mode} is not valid"
        end

        # We need to find the point at which the opcode, filename and mode
        # have ended and the options begin.
        offset = 0
        nulls = []
        @buffer.each_byte do |c|
            nulls.push offset if c == 0
            offset += 1
        end
        # There should be at least 3, the 0 in the opcode, the terminator for
        # the filename, and the terminator for the mode. If there are more,
        # then there are options.
        if nulls.length < 3
            raise TftpError, "Failed to parse nulls looking for options"
        elsif nulls.length > 3
            lower_bound = nulls[2] + 1
            @options = decode_options(@buffer[lower_bound..-1])
        end

        return self
    end

    protected

    # This method is a boolean validator that returns true if the blocksize
    # passed is valid, and false otherwise.
    def valid_blocksize?(blksize)
        blksize = blksize.to_i
        if blksize >= 8 and blksize <= 65464
            return true
        else
            return false
        end
    end

    # This method is a boolean validator that returns true of the mode passed
    # is valid, and false otherwise. The modes of 'netascii', 'octet' and
    # 'mail' are valid, even though only 'octet' is currently implemented.
    def valid_mode?(mode)
        case mode
        when "netascii", "octet", "mail"
            return true
        else
            return false
        end
    end
end

# The RRQ packet to request a download.
class TftpPacketRRQ < TftpPacketInitial
    def initialize
        super()
        @opcode = 1
    end
end

# The WRQ packet to request an upload.
class TftpPacketWRQ < TftpPacketInitial
    def initialize
        super()
        @opcode = 2
    end
end

#          2 bytes    2 bytes       n bytes
#          ---------------------------------
#   DATA  | 03    |   Block #  |    Data    |
#          ---------------------------------
class TftpPacketDAT < TftpPacket
    attr_accessor :data, :buffer, :blocknumber

    def initialize
        super()
        @opcode = 3
        @blocknumber = 0
        @data = nil
        @buffer = nil
    end

    def encode
        unless @opcode and @blocknumber and @data
            raise ArgumentError, "Required fields missing!"
        end
        # FIXME - check block size
        #@buffer = [@opcode, @blocknumber, @data].pack('nnC#{@data.length}')
        @buffer = [@opcode, @blocknumber].pack('nn')
        @buffer += @data
        return self
    end

    def decode
        unless @buffer
            raise ArgumentError, "Can't decode, buffer is empty."
        end
        struct = @buffer[0..3].unpack('nn')
        unless struct[0] == 3
            raise ArgumentError, "opcode #{struct[0]} is not a DAT!"
        end
        @blocknumber = struct[1]
        @data = @buffer[4..-1]
        return self
    end
end

#         2 bytes    2 bytes
#         -------------------
#  ACK   | 04    |   Block #  |
#         --------------------
class TftpPacketACK < TftpPacket
    attr_accessor :blocknumber, :buffer

    def initialize
        super()
        @opcode = 4
        @blocknumber = 0
        @buffer = nil
    end

    def encode
        unless @blocknumber
            raise ArgumentError, "blocknumber required"
        end
        @buffer = [@opcode, @blocknumber].pack('nn')
        return self
    end

    def decode
        unless @buffer
            raise ArgumentError, "Can't decode, buffer is empty."
        end
        struct = @buffer.unpack('nn')
        unless struct[0] == 4
            raise ArgumentError, "opcode #{struct[0]} is not an ACK!"
        end
        @blocknumber = struct[1]
        return self
    end
end

#          2 bytes  2 bytes        string    1 byte
#          ----------------------------------------
#  ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
#          ----------------------------------------
#      Error Codes
# 
#      Value     Meaning
# 
#      0         Not defined, see error message (if any).
#      1         File not found.
#      2         Access violation.
#      3         Disk full or allocation exceeded.
#      4         Illegal TFTP operation.
#      5         Unknown transfer ID.
#      6         File already exists.
#      7         No such user.
#      8         Failed negotiation
class TftpPacketERR < TftpPacket
    attr_reader :extended_errmsg
    attr_accessor :errorcode, :errmsg, :buffer
    ErrMsgs = [
        'Not defined, see error message (if any).',
        'File not found.',
        'Access violation.',
        'Disk full or allocation exceeded.',
        'Illegal TFTP operation.',
        'Unknown transfer ID.',
        'File already exists.',
        'No such user.',
        'Failed negotiation.'
        ]

    def initialize
        super()
        @opcode = 5
        @errorcode = 0
        @errmsg = nil
        @extended_errmsg = nil
        @buffer = nil
    end

    def encode
        unless @opcode and @errorcode
            raise ArgumentError, "Required params missing."
        end
        @errmsg = ErrMsgs[@errorcode] unless @errmsg
        format = 'nn' + "a#{@errmsg.length}" + 'x'
        @buffer = [@opcode, @errorcode, @errmsg].pack(format)
        return self
    end

    def decode
        unless @buffer
            raise ArgumentError, "Can't decode, buffer is empty."
        end
        struct = @buffer.unpack("nnZ*")
        unless struct[0] == 5
            raise ArgumentError, "opcode #{struct[0]} is not an ERR"
        end
        @errorcode = struct[1]
        @errmsg = struct[2]
        @extended_errmsg = ErrMsgs[@errorcode]
        return self
    end

end

#  +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
#  |  opc  |  opt1  | 0 | value1 | 0 |  optN  | 0 | valueN | 0 |
#  +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
class TftpPacketOACK < TftpPacket
    def initialize
        super()
        @opcode = 6
    end

    def encode
        datalist = [@opcode]
        format = 'n'
        options.each do |key, val|
            format += "a#{key.to_s.length}x"
            format += "a#{val.to_s.length}x"
            datalist.push key
            datalist.push val
        end
        @buffer = datalist.pack(format)
        return self
    end

    def decode
        opcode = @buffer[0..1].unpack('n')[0]
        unless opcode == @opcode
            raise ArgumentError, "opcode #{opcode} is not an OACK"
        end

        @options = decode_options(@buffer[2..-1])
        return self
    end
end

class TftpPacketFactory
    def initialize
    end

    def create(opcode)
        return case opcode
            when 1 then TftpPacketRRQ
            when 2 then TftpPacketWRQ
            when 3 then TftpPacketDAT
            when 4 then TftpPacketACK
            when 5 then TftpPacketERR
            when 6 then TftpPacketOACK
            else raise ArgumentError, "Unsupported opcode: #{opcode}"
        end.new
    end

    def parse(buffer)
        unless buffer
            raise ArgumentError, "buffer cannot be empty"
        end
        opcode = buffer[0..1].unpack('n')[0]
        packet = create(opcode)
        packet.buffer = buffer
        packet.decode
        return packet
    end
end

class TftpSession
    attr_accessor :options, :state
    attr_reader :dups, :errors

    def initialize
        # Agreed upon session options
        @options = {}
        # State of the session, can be one of
        # nil   - No state yet
        # :rrq  - Just sent rrq, waiting for response
        # :wrq  - Just sent wrq, waiting for response
        # :dat  - transferring data
        # :oack - Received oack, negotiating options
        # :ack  - Acknowledged oack, waiting for response
        # :err  - Fatal problems, giving up
        # :done - Session is over, file transferred
        @state = nil
        @dups = 0
        @errors = 0
        @blksize = DefBlkSize
    end
end

class TftpServer < TftpSession
    def initialize
        super()
        @iface = nil
        @port = nil
        @root = nil
        @sessions = []
    end

    # This method starts a server listening on a given port, to serve up files
    # at a given path. It takes an optional ip to bind to, which defaults to
    # localhost (127.0.0.1).
    def listen(port, path, iface="127.0.0.1")
        @iface = iface
        @port = port
        @root = path
        sock = UDPSocket.new
        sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
        #sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, SockTimeout)
        sock.bind(iface, port)
        $tftplog.info('tftp+') { "Bound to #{iface} on port #{port}" }

        factory = TftpPacketFactory.new
        retry_count = 0
        loop do
            $tftplog.debug('tftp+') { "Waiting for incoming datagram..." }
            msg = sender = nil
            begin
                status = Timeout::timeout(SockTimeout) {
                    msg, sender = sock.recvfrom(MaxBlkSize)
                }
            rescue Timeout::Error => details
                retry_count += 1
                if retry_count > MaxRetry
                    msg = "Timeout! Max retries exceeded. Giving up."
                    $tftplog.error('tftp+') { msg }
                    raise TftpError, msg
                else
                    $tftplog.warn('tftp+') { "Timeout! Lets try again." }
                    next
                end
            end
            prot, rport, rhost, rip = sender

            pkt = factory.parse(msg)
            $tftplog.debug('tftp+') { "pkt is #{pkt}" }

            key = "#{rip}-#{rport}"
            handler = nil
            unless @sessions.has_key? key
                handler = TftpServerHandler.new(rhost, rport, key, root)
            else
                handler = @sessions[key]
            end
            handler.handle(pkt)
        end
    end
end

class TftpServerHandler < TftpSession
    def initialize(rhost, rport, key, root)
        super()
        @host = rhost
        @port = rport
        @key = key
        @root = root
    end

    def handle(pkt)
    end
end

class TftpClient < TftpSession
    attr_reader :host, :port

    def initialize(host, port)
        super()
        @host = host
        # Force the port to a string type.
        @iport = port.to_s
        @port = nil
        # FIXME - move host and port args to download method

        begin
            @address = Resolv::IPv4.create(@host)
        rescue ArgumentError => details
            # So, @host doesn't look like an IP. Resolve it.
            # A Resolv::ResolvError exception could be raised here, let it
            # filter up.
            @address = Resolv::DNS.new.getaddress(@host)
        end
    end

    # FIXME - this method is too big
    def download(filename, output, options={})
        @blksize = options[:blksize] if options.has_key? :blksize
        $tftplog.debug('tftp+') { "Opening output file #{output}" }
        fout = File.open(output, "w")
        sock = UDPSocket.new
       
        pkt = TftpPacketRRQ.new
        pkt.filename = filename
        pkt.mode = 'octet' # FIXME - shouldn't hardcode this
        pkt.options = options
        $tftplog.info('tftp+') { "Sending download request for #{filename}" }
        $tftplog.info('tftp+') { "host = #{@host}, port = #{@iport}" }
        sock.send(pkt.encode.buffer, 0, @host, @iport)
        @state = :rrq

        factory = TftpPacketFactory.new

        blocknumber = 1
        retry_count = 0
        loop do
            $tftplog.debug('tftp+') { "Waiting for incoming datagram..." }
            msg = sender = nil
            begin
                status = Timeout::timeout(SockTimeout) {
                    msg, sender = sock.recvfrom(MaxBlkSize)
                }
            rescue Timeout::Error => details
                retry_count += 1
                if retry_count > MaxRetry
                    msg = "Timeout! Max retries exceeded. Giving up."
                    $tftplog.error('tftp+') { msg }
                    raise TftpError, msg
                else
                    $tftplog.debug('tftp+') { "Timeout! Lets try again." }
                    next
                end
            end
            prot, rport, rhost, rip = sender
            $tftplog.info('tftp+') { "Received #{msg.length} byte packet" }
            $tftplog.debug('tftp+') { "Remote port is #{rport} and remote host is #{rhost}" }

            if @address.to_s != rip
                # Skip it
                @errors += 1
                $stderr.write "It is a rogue packet! #{sender[1]} #{sender[2]}\n"
                next
            elsif @port and @port != rport.to_s
                # Skip it
                @errors += 1
                $stderr.write "It is a rogue packet! #{sender[1]} #{sender[2]}\n"
                next
            else not @port
                # Set this as our TID
                $tftplog.info('tftp+') { "Set remote TID to #{@port}" }
                @port = rport.to_s
            end

            pkt = factory.parse(msg)
            $tftplog.debug('tftp+') { "pkt is #{pkt}" }

            # FIXME - Refactor this into separate methods to handle each case.
            if pkt.is_a? TftpPacketRRQ
                # Skip it, but info('tftp+')rm the sender.
                err = TftpPacketERR.new
                err.errorcode = 4 # illegal op
                sock.send(err.encode.buffer, 0, @host, @port)
                @errors += 1
                $stderr.write "It is a RRQ packet in download, state #{@state}\n"

            elsif pkt.is_a? TftpPacketWRQ
                # Skip it, but info('tftp+')rm the sender.
                err = TftpPacketERR.new
                err.errorcode = 4 # illegal op
                sock.send(err.encode.buffer, 0, @host, @port)
                @errors += 1
                $stderr.write "It is a WRQ packet in download, state #{@state}\n"

            elsif pkt.is_a? TftpPacketACK
                # Skip it, but info('tftp+')rm the sender.
                err = TftpPacketERR.new
                err.errorcode = 4 # illegal op
                sock.send(err.encode.buffer, 0, @host, @port)
                @errors += 1
                $stderr.write "It is a ACK packet in download, state #{@state}\n"

            elsif pkt.is_a? TftpPacketERR
                @errors += 1
                raise TftpError, "ERR packet: #{pkt.errmsg}"

            elsif pkt.is_a? TftpPacketOACK
                unless @state == :rrq
                    @errors += 1
                    $stderr.write "It is a OACK in state #{@state}"
                    next
                end

                @state = :oack
                # Are the acknowledged options the same as ours?
                # FIXME - factor this into the OACK class?
                if pkt.options
                    pkt.options do |optname, optval|
                        case optname
                        when :blksize
                            # The blocksize can be <= what we proposed.
                            unless options.has_key? :blksize
                                # Hey, we didn't ask for a blocksize option...
                                err = TftpPacketERR.new
                                err.errorcode = 8 # failed negotiation
                                sock.send(err.encode.buffer, 0, @host, @port)
                                raise TftpError, "It is a OACK with blocksize when we didn't ask for one."
                            end

                            if optval <= options[:blksize] and optval >= MinBlkSize
                                # Valid. Lets use it.
                                options[:blksize] = optval
                            end
                        else
                            # FIXME - refactor err packet handling from above...
                            # Nothing that we don't know of should be in the
                            # oack packet.
                            err = TftpPacketERR.new
                            err.errorcode = 8 # failed negotiation
                            sock.send(err.encode.buffer, 0, @host, @port)
                            raise TftpError, "Failed to negotiate options: #{pkt.options}"
                        end
                    end
                    # SUCCESSFUL NEGOTIATION
                    # If we're here, then we're happy with the options in the
                    # OACK. Send an ACK of block 0 to ACK the OACK.
                    # FIXME - further negotiation required here?
                    ack = TftpPacketACK.new
                    ack.blocknumber = 0
                    sock.send(ack.encode.buffer, 0, @host, @port)
                    @state = :ack
                else
                    # OACK with no options?
                    err = TftpPacketERR.new
                    err.errorcode = 8 # failed negotiation
                    sock.send(err.encode.buffer, 0, @host, @port)
                    raise TftpError, "OACK with no options"
                end

                # Done parsing. If we didn't raise an exception, then we need
                # to send an ACK to the server, with block number 0.
                ack = TftpPacketACK.new
                ack.blocknumber = 0
                $tftplog.info('tftp+') { "Sending ACK to OACK" }
                sock.send(ack.encode.buffer, 0, @host, @port)
                @state = :ack

            elsif pkt.is_a? TftpPacketDAT
                # If the state is :rrq, and we sent options, then the
                # server didn't send us an oack, and the options were refused.
                # FIXME - we need to handle all possible options and set them
                # back to their defaults here, not just blocksize.
                if @state == :rrq and options.has_key? :blksize
                    @blksize = DefBlkSize
                end

                @state = :dat
                $tftplog.info('tftp+') { "It is a DAT packet, block #{pkt.blocknumber}" }
                $tftplog.debug('tftp+') { "DAT size is #{pkt.data.length}" }

                ack = TftpPacketACK.new
                ack.blocknumber = pkt.blocknumber

                $tftplog.info('tftp+') { "Sending ACK to block #{ack.blocknumber}" }
                sock.send(ack.encode.buffer, 0, @host, @port)

                # Check for dups
                if pkt.blocknumber <= blocknumber
                    $tftplog.warn('tftp+') { "It is a DUP for block #{blocknumber}" }
                    @dups += 1
                elsif pkt.blocknumber = blocknumber+1
                    $tftplog.debug('tftp+') { "It is a properly ordered DAT packet" }
                    blocknumber += 1
                else
                    # Skip it, but info('tftp+')rm the sender.
                    err = TftpPacketERR.new
                    err.errorcode = 4 # illegal op
                    sock.send(err.encode.buffer, 0, @host, @port)
                    @errors += 1
                    $stderr.write "It is a future packet!\n"
                end

                # Call any block passed.
                if block_given?
                    yield pkt
                end

                # Write the data to the file.
                fout.print pkt.data
                # If the size is less than our blocksize, we're done.
                $tftplog.debug('tftp+') { "pkt.data.length is #{pkt.data.length}" }
                if pkt.data.length < @blksize
                    $tftplog.info('tftp+') { "It is a last packet." }
                    fout.close
                    @state = :done
                    break
                end
            else
                msg = "It is an unknown packet: #{pkt}"
                $tftplog.error('tftp+') { msg }
                raise TftpError, msg
            end
        end
    end
end

# If invoked directly...
if __FILE__ == $0
    # Simple client maybe?
end
