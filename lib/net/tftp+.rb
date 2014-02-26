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
SendTimeout     = 5
MaxDups         = 20
Assertions      = true
MaxRetry        = 5
MaxBlockNum     = 65535
DefRoot         = '/tftpboot'
MaxBindAttempts = 5

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

# Convenience function for debug logging.
def debug(msg)
    $tftplog.debug('tftp+') { msg }
end

# Convenience function for info logging.
def info(msg)
    $tftplog.info('tftp+') { msg }
end

# Convenience function for warn logging.
def warn(msg)
    $tftplog.warn('tftp+') { msg }
end

# Convenience function for error logging.
def error(msg)
    $tftplog.error('tftp+') { msg }
end

# This class is a convenience for defining the common tftp error codes, and
# making them more readable in the code.
class TftpErrorType
    @notDefined  = 0
    @fileNotFound = 1
    @accessViolation = 2
    @diskFull = 3
    @illegalTftpOp = 4
    @unknownTID = 5
    @fileAlreadyExists = 6
    @noSuchUser = 7
    @failedNegotiation = 8
    class <<self
        attr_reader :notDefined, :fileNotFound, :accessViolation
        attr_reader :diskFull, :illegalTftpOp, :unknownTID
        attr_reader :fileAlreadyExists, :noSuchUser, :failedNegotiation
    end
end

# This exception is used to signal errors.
class TftpError < RuntimeError
end

# This exception is used to signal success to the server instance.
class TftpSuccess < Exception
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
            debug "looping on key #{key}, val #{val}"
            debug "class of key is #{key.class}"
            tftpassert("options keys must be symbols") { key.class == Symbol }
            myopts[key.to_s] = val.to_s
        end
        @options = myopts
    end

    # A getter for the options hash.
    def options
        return @options
    end

    private

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
            debug "decoded option #{name} with value #{value}"
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
        unless TftpPacketInitial.valid_mode? @mode
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

    private

    # This method is a boolean validator that returns true if the blocksize
    # passed is valid, and false otherwise.
    # FIXME - is anyone calling this?
    def self.valid_blocksize?(blksize)
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
    def self.valid_mode?(mode)
        case mode
        # FIXME - implement support for netascii. don't care about mail
        #when "netascii", "octet", "mail"
        when "octet"
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
        debug "DAT encode: @opcode is #{@opcode}"
        debug "DAT encode: @blocknumber is #{@blocknumber}"
        debug "DAT encode: @data has #{@data.length} bytes in it"
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
    # FIXME - Reevaluate the ErrMsg, and whether we encourage senderror to
    # expect one.
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
        unless buffer and buffer.class == String
            raise ArgumentError, "buffer cannot be empty"
        end
        begin
            opcode = buffer[0..1].unpack('n')[0]
            packet = create(opcode)
            packet.buffer = buffer
            packet.decode
            return packet
        rescue 
            raise TftpError, "Parsing errors, packet looks bad."
        end
    end
end

class TftpSession
    attr_accessor :options, :state
    attr_reader :dups, :errors

    def initialize
        # Agreed upon session options
        @options = {}
        # FIXME - should we make the state an object of its own?
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
        @options = { :blksize => DefBlkSize }
    end

    # This method is used to send an error packet to a given address and port,
    # with an given error code.
    def senderror(sock, errorcode, address, port)
        @errors += 1
        err = TftpPacketERR.new
        err.errorcode = errorcode
        sock.send(err.encode.buffer, 0, address, port)
    end
end

# This server instance currently listens on a single specified port to
# initiate a session. From there it waits in a select() loop on all sockets
# for itself and all handlers, dispatching ready sockets to their handlers and
# instantiating new handlers as needed.
class TftpServer < TftpSession
    def initialize(root)
        super()
        @root = root
        @iface = nil
        @port = nil
        @handlers = {}
    end

    # This method starts a server listening on a given port, to serve up files
    # at a given path. It takes an optional ip to bind to, which defaults to
    # INADDR_ANY.
    def listen(port, path, iface="")
        @iface = iface
        @port = port
        @root = path
        main_sock = UDPSocket.new
        main_sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
        main_sock.bind(iface, port)
        info "Bound to #{@iface} on port #{@port}"

        factory = TftpPacketFactory.new
        retry_count = 0
        loop do
            allsockets = []
            allsockets << main_sock
            @handlers.each do |key, val|
                allsockets << val.sock
            end
            debug "Performing select on all sockets"
            debug "allsockets array is #{allsockets}"
            selectarr = select(allsockets, nil, nil, SockTimeout)
            readysocks = selectarr ? selectarr[0] : []

            deletion_list = []

            # FIXME - this loop is really large...
            readysocks.each do |readysock|
                if readysock.equal?(main_sock)
                    debug "Traffic on the main socket"
                    msg, sender = readysock.recvfrom(MaxBlkSize)
                    prot, rport, rhost, rip = sender

                    pkt = factory.parse(msg)
                    debug "pkt is a #{pkt}"

                    if pkt.is_a? TftpPacketRRQ
                        debug "Handling packet as an RRQ"

                        key = "#{rip}:#{rport}"
                        handler = nil
                        unless @handlers.has_key?(key)
                            handler = TftpServerHandler.new(rhost,
                                                            rport,
                                                            key,
                                                            @root,
                                                            @iface,
                                                            factory,
                                                            :rrq)
                            @handlers[key] = handler
                            begin
                                handler.handle(pkt)
                            rescue TftpError => details
                                error "Fatal exception thrown from handler at creation #{key}: #{details}"
                                deletion_list.push(key)
                            end
                            # Note: A TftpSuccess exception isn't possible
                            # here.
                        else
                            senderror(main_sock,
                                      TftpErrorType.unknownTID,
                                      rhost,
                                      rport)
                            error "Received RRQ for session #{key}, which already exists"
                            @errors += 1
                            next
                        end
                    elsif pkt.is_a? TftpPacketWRQ
                        debug "Handling packet as a WRQ"

                        senderror(main_sock,
                                  TftpErrorType.illegalTftpOp,
                                  rhost,
                                  rport)
                        warn "Support for uploads not yet implemented."
                        next
                    else
                        debug "Handling packet as a non-RRQ/WRQ"
                        # FIXME - this will prevent symmetric udp from working
                        # if I ever care to implement it.
                        senderror(main_sock,
                                  TftpErrorType.illegalTftpOp,
                                  rhost,
                                  rport)
                        error "Only RRQ and WRQ operations are valid on the main socket."
                        @errors += 1
                        next
                    end
                else

                    debug "Not the main socket. Hunting for the right socket to match socket #{readysock}"
                    found = false
                    @handlers.each do |key, handler|
                        if readysock.equal?(handler.sock)
                            debug "Found it. Handler is #{handler.key}"
                            found = true
                            begin
                                handler.handle
                            rescue TftpSuccess => details
                                info "Successful transfer for handler #{key}: #{details}"
                                deletion_list.push(key)
                            rescue Exception => details
                                error "Fatal exception thrown from handler #{key}: #{details}"
                                deletion_list.push(key)
                            ensure
                                debug "Breaking out of handler iteration"
                                break
                            end
                        end
                    end

                    debug "About to process deletion list"
                    deletion_list.each do |key|
                        debug "Deleting handler #{key}"
                        @handlers.delete(key)
                    end
                
                    unless found
                        # FIXME - should I do more here?
                        error "Hey, I didn't find the handler for this packet!"
                        @errors += 1
                    end
                end
            end

            # Loop on each handler and see if they've timed-out.
            now = Time.now
            @handlers.each do |key, handler|
                if now - handler.timesent > SendTimeout
                    info "Handler #{key} has timed-out"
                    handler.timeout()
                end
            end
        end
    end
end

# The server handler class is responsible for handling a single tftp session.
# One of these will be instantiated per client.
class TftpServerHandler < TftpSession
    attr_reader :timesent, :sock, :key

    def initialize(rhost, rport, key, root, listen_ip, factory, state)
        debug "Instantiating a new handler:"
        debug "   rhost     = #{rhost}"
        debug "   rport     = #{rport}"
        debug "   key       = #{key}"
        debug "   root      = #{root}"
        debug "   listen_ip = #{listen_ip}"
        debug "   state     = #{state}"
        super()
        @host = rhost
        @port = rport
        @key = key
        @root = root
        @listen_ip = listen_ip
        @factory = factory
        @state = state
        @filename = nil
        @file = nil
        @mode = nil
        @blocknumber = 0
        @buffer = ""
        @timesent = 0

        @sock = get_socket()
    end

    # This method returns a UDP socket bound to a random, hopefully unused
    # port.
    def get_socket
        sock = UDPSocket.new
        sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)

        count = 0
        bound = false
        begin
            port = rand(2 ** 16 - 1024) + 1024
            debug "Attempting to bind to #{@listen_ip}:#{port}"
            sock.bind(@listen_ip, port)
            bound = true
        rescue 
            warn "Failed to bind to #{@listen_ip}:#{port}"
            if count < MaxBindAttempts
                count += 1
                redo
            end
        end

        if bound
            info "Handler #{@key} bound to #{@listen_ip} on port #{port}"
        else
            raise TftpError, "Can't seem to find a spare port to bind to."
        end

        return sock
    end

    # This method "informs" the handler that it has data waiting on its socket
    # that it must read. Optionally, an already read packet can be passed to
    # this method, in which case the handler will assume that the source of
    # the packet has already been validated.
    #
    # To shut down a handler, the handler raises an exception to the server
    # instance. TftpError is used to signal errors, while TftpSuccess is used
    # to signal success.
    # FIXME - this method is too big
    def handle(*pkt)
        recvpkt = nil
        if pkt.length > 0
            # handle passed data - we're trusting the Server to validate the
            # client here.
            recvpkt = pkt.shift
        else
            # need to read from our socket - UDP should ensure full reads
            msg, sender = @sock.recvfrom(MaxBlkSize)
            prot, rport, rhost, rip = sender
            if rport != @port or rhost != @host
                senderror(@sock,
                          TftpErrorType.unknownTID,
                          rhost,
                          rport)
                error "Handler #{@key} received traffic from #{rhost}:#{rport} " +
                      "but we're talking to client #{@host}:#{@port}"
                return
            end

            recvpkt = @factory.parse(msg)
        end

        # Process the packet based on its type and our state.
        if recvpkt.is_a? TftpPacketRRQ
            info "Received an RRQ from #{@host}:#{@port}"
            # If we're starting a download, we should be in state rrq.
            if @state == :rrq
                # Store the filename and mode.
                @filename = recvpkt.filename
                info "Requested filename is #{@filename}"

                @mode = recvpkt.mode
                info "Requested mode is #{@mode}"

                # FIXME - We only support octet mode for now.
                if @mode != 'octet'
                    senderror(@sock,
                              TftpErrorType.illegalTftpOp,
                              @host,
                              @port)
                    @errors += 1
                    raise TftpError, "Unsupported mode: #{@mode}"
                end

                # If there are options, negotiate.
                if recvpkt.options.length > 0
                    debug "There are options in the RRQ: #{recvpkt.options}"
                    # The only option we support is blksize.
                    if recvpkt.options.key?(:blksize)
                        # Note, we only consider ourselves in oack state if
                        # there were supported options.
                        debug "Client requested blksize #{@options[:blksize]}"
                        if TftpPacketRRQ.valid_blocksize?(recvpkt.options[:blksize])
                            @state = :oack
                            @options[:blksize] = recvpkt.options[:blksize]
                        else
                            error "Invalid blocksize #{recvpkt.options[:blksize]}"
                            @errors += 1
                            senderror(@sock,
                                      TftpErrorType.illegalTftpOp,
                                      @host,
                                      @port)
                        end
                    end
                end

                # Do we need to send an oack? If we're in oack state, and
                # we've set any supported options, then yes, we do.
                if @state == :oack
                    oack = TftpPacketOACK.new
                    oack.options = @options
                    @sock.send(oack.encode.buffer, 0, @host, @port)
                    @timesent = Time.now
                else
                    start_download()
                end

            else
                senderror(@sock,
                          TftpErrorType.illegalTftpOp,
                          @host,
                          @port)
                error "Received an rrq from #{@host}:#{@port}, but we're in state #{@state}"
                @errors += 1
                return
            end

        elsif recvpkt.is_a? TftpPacketWRQ
            # FIXME - check state here
            senderror(@sock, TftpErrorType.illegalTftpOp, @host, @port)
            @errors += 1
            raise TftpError, "WRQ not yet supported"

        elsif recvpkt.is_a? TftpPacketACK
            # If we're in state oack and the blocknumber is 0, it's an ACK to
            # the OACK. Otherwise, it's an ACK to a DAT packet...hopefully.
            if @state == :oack and recvpkt.blocknumber == 0
                info "OACK acknowledged by client. Starting download."
                start_download()
            elsif @state == :dat or @state == :fin
                debug "Received ACK to block #{recvpkt.blocknumber}"
                if recvpkt.blocknumber == @blocknumber
                    if @state == :fin
                        raise TftpSuccess, "Successful transfer."
                    else
                        debug "Received valid ACK. Sending next DAT."
                        send_dat()
                    end
                elsif recvpkt.blocknumber < @blocknumber
                    warn "Received duplicate ACK for block #{recvpkt.blocknumber}"
                    @dups += 1
                    return
                else
                    error "Received ACK from the future, block #{recvpkt.blocknumber}"
                    @errors += 1
                    return
                end
            else
                senderror(@sock,
                          TftpErrorType.illegalTftpOp,
                          @host,
                          @port)
                @errors += 1
                raise TftpError, "Received invalid ACK from client"
            end

        elsif recvpkt.is_a? TftpPacketERR
            @errors += 1
            raise TftpError, "Received error packet from client: #{recvpkt}"
        else
            # Unsupported packet type
            senderror(@sock,
                      TftpErrorType.illegalTftpOp,
                      @host,
                      @port)
            @errors += 1
            raise TftpError, "Unsupported packet type in server: #{recvpkt}"
        end
    end

    # This method validates the current filename requested, and initiates the
    # download if everything is ok.
    def start_download
        @state = :dat
        # Only check if there are any slashes in the filename.
        if @filename =~ %r{^/}
            senderror(main_sock,
                      TftpErrorType.illegalTftpOp,
                      rhost,
                      rport)
            raise TftpError, "Absolute paths in filenames not permitted"
        elsif @filename =~ %r{../}
            senderror(main_sock,
                      TftpErrorType.illegalTftpOp,
                      rhost,
                      rport)
            raise TftpError, ".. not permitted in filenames"
        elsif @filename =~ %r{/}
            # Make sure it's in our root.
            @filename = File.expand_path(@filename)
            unless @filename =~ /^@root/
                # It's not in our root. Send an error.
                senderror(main_sock,
                          TftpErrorType.illegalTftpOp,
                          rhost,
                          rport)
                raise TftpError, "File request for #{@filename} outside of root"
            end
        end

        # If it's ok, open the file and send the first DAT.
        path = @root + '/' + @filename
        if File.exists?(path)
            debug "Opening file #{path} for reading"
            @file = File.new(path, "rb")
            debug "File open: #{@file.inspect}"
            send_dat()
        else
            senderror(sock,
                        TftpErrorType.fileNotFound,
                        @host,
                        @port)
            raise TftpError, "File does not exist"
        end
    end

    # This method sends a single DAT packet, the next one in the series.
    # It takes an optional :resend parameter, in which case it resends the
    # last DAT instead of sending the next one.
    def send_dat(*args)
        debug "send_dat: args is #{args}"
        opts = {}
        if args.length > 0 and args[0].class == 'Hash'
            opts = args[0]
        end

        unless opts.key?(:resend) and opts[:resend]
            blksize = @options[:blksize].to_i
            debug "Reading #{blksize} bytes from file #{@filename}"
            @buffer = @file.read(blksize)
            debug "@buffer is now #{@buffer.class}"
            debug "Read #{@buffer.length} bytes into buffer"
            if @file.eof
                info "End of file #{@filename} detected."
                @file.close
                @state = :fin
            end

            @blocknumber += 1
            if @blocknumber > MaxBlockNum
                debug "Blocknumber rolled over to zero"
                @blocknumber = 0
            end
        else
            warn "Resending block number #{@blocknumber}"
        end

        dat = TftpPacketDAT.new
        dat.data = @buffer
        dat.blocknumber = @blocknumber
        debug "Sending DAT packet #{@blocknumber}"
        @sock.send(dat.encode.buffer, 0, @host, @port)
        @timesent = Time.now
    end

    # This method handles the timeout case, where the handler has send a
    # packet to the client and not received a response.
    def timeout
        @dups += 1
        send_dat(:resend => true)
        # FIXME - need to give up eventually!
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
            begin
                @address = Resolv::IPv4.create(TCPSocket.gethostbyname(@host)[3])
            rescue SocketError => details
                # Reraise the exception for now.
                raise
            end
        end
    end

    # FIXME - this method is too big
    def download(filename, output, options={})
        @options[:blksize] = options[:blksize] if options.has_key?(:blksize)
        debug "Opening output file #{output}"
        fout = File.open(output, "w")
        sock = UDPSocket.new
       
        pkt = TftpPacketRRQ.new
        pkt.filename = filename
        pkt.mode = 'octet' # FIXME - shouldn't hardcode this
        pkt.options = options
        info "Sending download request for #{filename}"
        info "host = #{@host}, port = #{@iport}"
        sock.send(pkt.encode.buffer, 0, @host, @iport)
        @state = :rrq

        factory = TftpPacketFactory.new

        blocknumber = 1
        retry_count = 0
        loop do
            debug "Waiting for incoming datagram..."
            msg = sender = nil
            begin
                status = Timeout::timeout(SockTimeout) {
                    msg, sender = sock.recvfrom(MaxBlkSize)
                }
            rescue Timeout::Error => details
                retry_count += 1
                if retry_count > MaxRetry
                    msg = "Timeout! Max retries exceeded. Giving up."
                    error msg
                    raise TftpError, msg
                else
                    debug "Timeout! Lets try again."
                    next
                end
            end
            prot, rport, rhost, rip = sender
            info "Received #{msg.length} byte packet"
            debug "Remote port is #{rport} and remote host is #{rhost}"

            if @address.to_s != rip
                # Skip it
                @errors += 1
                error "It is a rogue packet! #{sender[1]} #{sender[2]}"
                next
            elsif @port and @port != rport.to_s
                # Skip it
                @errors += 1
                error "It is a rogue packet! #{sender[1]} #{sender[2]}"
                next
            else not @port
                # Set this as our TID
                debug "@port was #{@port}"
                @port = rport.to_s
                info "Set remote TID to #{@port}"
            end

            pkt = factory.parse(msg)
            debug "pkt is #{pkt}"

            # FIXME - Refactor this into separate methods to handle each case.
            if pkt.is_a? TftpPacketRRQ
                # Skip it, but info('tftp+')rm the sender.
                senderror(sock,
                          TftpErrorType.illegalTftpOp,
                          @host,
                          @port)
                @errors += 1
                debug "It is a RRQ packet in download, state #{@state}"

            elsif pkt.is_a? TftpPacketWRQ
                # Skip it, but info('tftp+')rm the sender.
                senderror(sock,
                          TftpErrorType.illegalTftpOp,
                          @host,
                          @port)
                @errors += 1
                debug "It is a WRQ packet in download, state #{@state}"

            elsif pkt.is_a? TftpPacketACK
                # Skip it, but info('tftp+')rm the sender.
                senderror(sock,
                          TftpErrorType.illegalTftpOp,
                          @host,
                          @port)
                @errors += 1
                debug "It is a ACK packet in download, state #{@state}"

            elsif pkt.is_a? TftpPacketERR
                @errors += 1
                raise TftpError, "ERR packet: #{pkt.errmsg}"

            elsif pkt.is_a? TftpPacketOACK
                unless @state == :rrq
                    senderror(sock,
                              TftpErrorType.illegalTftpOp,
                              @host,
                              @port)
                    @errors += 1
                    debug "It is an OACK in state #{@state}"
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
                            unless options.has_key?(:blksize)
                                # Hey, we didn't ask for a blocksize option...
                                senderror(sock,
                                          TftpErrorType.failedNegotiation,
                                          @host,
                                          @port)
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
                            senderror(sock,
                                      TftpErrorType.failedNegotiation,
                                      @host,
                                      @port)
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
                    senderror(sock,
                              TftpErrorType.failedNegotiation,
                              @host,
                              @port)
                    raise TftpError, "OACK with no options"
                end

                # Done parsing. If we didn't raise an exception, then we need
                # to send an ACK to the server, with block number 0.
                ack = TftpPacketACK.new
                ack.blocknumber = 0
                info "Sending ACK to OACK"
                sock.send(ack.encode.buffer, 0, @host, @port)
                @state = :ack

            elsif pkt.is_a? TftpPacketDAT
                # If the state is :rrq, and we sent options, then the
                # server didn't send us an oack, and the options were refused.
                # FIXME - we need to handle all possible options and set them
                # back to their defaults here, not just blocksize.
                if @state == :rrq and options.has_key?(:blksize)
                    @options[:blksize] = DefBlkSize
                end

                @state = :dat
                info "It is a DAT packet, block #{pkt.blocknumber}"
                debug "DAT size is #{pkt.data.length}"

                ack = TftpPacketACK.new
                ack.blocknumber = pkt.blocknumber

                info "Sending ACK to block #{ack.blocknumber}"
                sock.send(ack.encode.buffer, 0, @host, @port)

                # Check for dups
                if pkt.blocknumber <= blocknumber
                    warn "It is a DUP for block #{blocknumber}"
                    @dups += 1
                elsif pkt.blocknumber = blocknumber+1
                    debug "It is a properly ordered DAT packet"
                    blocknumber += 1
                else
                    # Skip it, but info('tftp+')rm the sender.
                    senderror(sock,
                              TftpErrorType.illegalTftpOp,
                              @host,
                              @port)
                    @errors += 1
                    debug "It is a future packet!"
                end

                # Call any block passed.
                if block_given?
                    yield pkt
                end

                # Write the data to the file.
                fout.print pkt.data
                # If the size is less than our blocksize, we're done.
                debug "pkt.data.length is #{pkt.data.length}"
                if pkt.data.length < @options[:blksize]
                    info "It is a last packet."
                    fout.close
                    @state = :done
                    break
                end
            else
                msg = "It is an unknown packet: #{pkt}"
                error msg
                raise TftpError, msg
            end
        end
    end
end

# If invoked directly...
if __FILE__ == $0
    # Simple client maybe?
end
