# A Ruby library for Trivial File Transfer Protocol.
# Supports the following RFCs
# RFC 1350 - THE TFTP PROTOCOL (REVISION 2)
# RFC 2347 - TFTP Option Extension # FIXME - not yet
# RFC 2348 - TFTP Blocksize Option # FIXME - not yet

require 'socket'
require 'timeout'

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

def assert(&code)
    if not code.call and Assertions
        raise RuntimeError, "Assertion Failed", caller
    end
end

class TftpError < IOError
end

class TftpPacket
    attr_accessor :opcode, :buffer
    def initialize
        @opcode = 0
        @buffer = nil
    end

    def encode
        raise NotImplementedError
    end

    def decode
        raise NotImplementedError
    end

    protected

    def decode_with_options(buffer)
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
            puts "decoded option #{name} with value #{value}"
        end
        return options
    end
end

class TftpPacketInitial < TftpPacket
    attr_accessor :filename, :mode, :options
    #         2 bytes    string   1 byte     string   1 byte
    #         -----------------------------------------------
    # RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
    # WRQ    -----------------------------------------------
    #      +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
    #      |  opc  |filename| 0 |  mode  | 0 | blksize| 0 | #octets| 0 |
    #      +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
    def initialize
        super()
        @filename = nil
        @mode = nil
        @options = {}
    end

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
            key = key.to_s
            value = value.to_s
            format += "a#{key.length}x"
            format += "a#{value.length}x"
            datalist.push key
            datalist.push value
        end

        @buffer = datalist.pack(format)
        return self
    end

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
            @options = decode_with_options(@buffer[lower_bound..-1])
        end

        return self
    end

    protected

    def valid_blocksize?(blksize)
        blksize = blksize.to_i
        if blksize >= 8 and blksize <= 65464
            return true
        else
            return false
        end
    end

    def valid_mode?(mode)
        case mode
        when "netascii", "octet", "mail"
            return true
        else
            return false
        end
    end
end

class TftpPacketRRQ < TftpPacketInitial
    def initialize
        super()
        @opcode = 1
    end
end

class TftpPacketWRQ < TftpPacketInitial
    def initialize
        super()
        @opcode = 2
    end
end

class TftpPacketDAT < TftpPacket
    attr_accessor :data, :buffer, :blocknumber
    #        2 bytes    2 bytes       n bytes
    #        ---------------------------------
    # DATA  | 03    |   Block #  |    Data    |
    #        ---------------------------------
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

class TftpPacketACK < TftpPacket
    attr_accessor :blocknumber, :buffer
    #        2 bytes    2 bytes
    #        -------------------
    # ACK   | 04    |   Block #  |
    #        --------------------
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

class TftpPacketERR < TftpPacket
    #         2 bytes  2 bytes        string    1 byte
    #         ----------------------------------------
    # ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
    #         ----------------------------------------
    #     Error Codes
    # 
    #     Value     Meaning
    # 
    #     0         Not defined, see error message (if any).
    #     1         File not found.
    #     2         Access violation.
    #     3         Disk full or allocation exceeded.
    #     4         Illegal TFTP operation.
    #     5         Unknown transfer ID.
    #     6         File already exists.
    #     7         No such user.
    #     8         Failed negotiation
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

class TftpPacketOACK < TftpPacket
    #  +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
    #  |  opc  |  opt1  | 0 | value1 | 0 |  optN  | 0 | valueN | 0 |
    #  +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
    attr_accessor :options
    def initialize
        super()
        @opcode = 6
        @options = {}
    end

    def encode
        datalist = [@opcode]
        format = 'n'
        options.each do |key, val|
            format += "a#{key.to_s.length}x"
            format += "a#{val.to_s.length}x"
            datalist.push key.to_s
            datalist.push val.to_s
        end
        @buffer = datalist.pack(format)
        return self
    end

    def decode
        opcode = @buffer[0..1].unpack('n')[0]
        unless opcode == @opcode
            raise ArgumentError, "opcode #{opcode} is not an OACK"
        end

        @options = decode_with_options(@buffer[2..-1])
        return self
    end
end

class TftpPacketFactory
    def initialize
    end

    def create(opcode)
        classname = nil
        packet = nil
        case opcode
        when 1
            classname = 'TftpPacketRRQ'
        when 2
            classname = 'TftpPacketWRQ'
        when 3
            classname = 'TftpPacketDAT'
        when 4
            classname = 'TftpPacketACK'
        when 5
            classname = 'TftpPacketERR'
        when 6
            classname = 'TftpPacketOACK'
        else
            raise ArgumentError, "Unsupported opcode: #{opcode}"
        end
        eval "packet = #{classname}.new"
        return packet
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
        puts "Bound to #{iface} on port #{port}"

        factory = TftpPacketFactory.new
        retry_count = 0
        loop do
            # FIXME - timeout
            puts "Waiting for incoming datagram..."
            msg = sender = nil
            begin
                status = Timeout::timeout(SockTimeout) {
                    msg, sender = sock.recvfrom(MaxBlkSize)
                }
            rescue Timeout::Error => details
                retry_count += 1
                if retry_count > MaxRetry
                    raise TftpError, "Timeout! Max retries exceeded. Giving up."
                else
                    puts "Timeout! Lets try again."
                    next
                end
            end
            prot, rport, rhost, rip = sender

            pkt = factory.parse(msg)
            puts "pkt is #{pkt}"

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
        @port = port.to_s
        # FIXME - move host and part args to download method
    end

    # FIXME - this method is too big
    def download(filename, output, options={})
        @blksize = options[:blksize] if options.has_key? :blksize
        puts "Opening output file #{output}"
        fout = File.open(output, "w")
        sock = UDPSocket.new
        #sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, SockTimeout)
       
        pkt = TftpPacketRRQ.new
        pkt.filename = filename
        pkt.mode = 'octet' # FIXME - shouldn't hardcode this
        pkt.options = options
        puts "Sending download request for #{filename}"
        puts "host = #{@host}, port = #{@port}"
        sock.send(pkt.encode.buffer, 0, @host, @port)
        @state = :rrq

        factory = TftpPacketFactory.new

        blocknumber = 1
        retry_count = 0
        loop do
            # FIXME - we need to timeout here!
            puts "Waiting for incoming datagram..."
            msg = sender = nil
            begin
                status = Timeout::timeout(SockTimeout) {
                    msg, sender = sock.recvfrom(MaxBlkSize)
                }
            rescue Timeout::Error => details
                retry_count += 1
                if retry_count > MaxRetry
                    raise TftpError, "Timeout! Max retries exceeded. Giving up."
                else
                    puts "Timeout! Lets try again."
                    next
                end
            end
            prot, rport, rhost, rip = sender
            puts "Got one, #{msg.length} bytes in size"
            puts "Remote port is #{rport} and remote host is #{rhost}"

            if @port != rport.to_s or @host != rhost.to_s
                # Skip it, but inform the sender.
                err = TftpPacketERR.new
                err.errorcode = 5 # unknown transfer id
                sock.send(err.encode.buffer, 0, rhost, rport)
                @errors += 1
                $stderr.write "Received rogue packet! #{sender[1]} #{sender[2]}\n"
                next
            end

            pkt = factory.parse(msg)
            puts "pkt is #{pkt}"

            # FIXME - Refactor this into separate methods to handle each case.
            if pkt.is_a? TftpPacketRRQ
                # Skip it, but inform the sender.
                err = TftpPacketERR.new
                err.errorcode = 4 # illegal op
                sock.send(err.encode.buffer, 0, @host, @port)
                @errors += 1
                $stderr.write "Received RRQ packet in download, state #{@state}\n"

            elsif pkt.is_a? TftpPacketWRQ
                # Skip it, but inform the sender.
                err = TftpPacketERR.new
                err.errorcode = 4 # illegal op
                sock.send(err.encode.buffer, 0, @host, @port)
                @errors += 1
                $stderr.write "Received WRQ packet in download, state #{@state}\n"

            elsif pkt.is_a? TftpPacketACK
                # Skip it, but inform the sender.
                err = TftpPacketERR.new
                err.errorcode = 4 # illegal op
                sock.send(err.encode.buffer, 0, @host, @port)
                @errors += 1
                $stderr.write "Received ACK packet in download, state #{@state}\n"

            elsif pkt.is_a? TftpPacketERR
                @errors += 1
                raise TftpError, "ERR packet: #{pkt.errmsg}"

            elsif pkt.is_a? TftpPacketOACK
                unless @state == :rrq
                    @errors += 1
                    $stderr.write "Received OACK in state #{@state}"
                    next
                end

                @state = :oack
                # Are the acknowledged options the same as ours?
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
                                raise TftpError, "Received OACK with blocksize when we didn't ask for one."
                            end

                            if optval <= options[:blksize] and optval >= MinBlkSize
                                # Valid. Lets use it.
                                options[:blksize] = optval
                            end
                        else
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
                puts "Sending ACK to OACK"
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
                puts "Received a DAT packet, block #{pkt.blocknumber}"
                puts "DAT size is #{pkt.data.length}"

                ack = TftpPacketACK.new
                ack.blocknumber = pkt.blocknumber

                puts "Sending ACK to block #{ack.blocknumber}"
                sock.send(ack.encode.buffer, 0, @host, @port)

                # Check for dups
                if pkt.blocknumber <= blocknumber
                    puts "Received a DUP for block #{blocknumber}"
                    @dups += 1
                elsif pkt.blocknumber = blocknumber+1
                    puts "Received properly ordered DAT packet"
                    blocknumber += 1
                else
                    # Skip it, but inform the sender.
                    err = TftpPacketERR.new
                    err.errorcode = 4 # illegal op
                    sock.send(err.encode.buffer, 0, @host, @port)
                    @errors += 1
                    $stderr.write "Received future packet!\n"
                end

                # Call any block passed.
                if block_given?
                    yield pkt
                end

                # Write the data to the file.
                fout.print pkt.data
                # If the size is less than our blocksize, we're done.
                puts "pkt.data.length is #{pkt.data.length}"
                if pkt.data.length < @blksize
                    puts "Received last packet."
                    fout.close
                    @state = :done
                    break
                end
            else
                raise TftpError, "Received unknown packet: #{pkt}"
            end
        end
    end
end

# If invoked directly...
if __FILE__ == $0
    # Simple client maybe?
end
