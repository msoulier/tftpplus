#!/usr/bin/env ruby

$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'net/tftp+'
require 'test/unit'

# Mock socket class
# FIXME - it should probably do more than this
class MockSock
    def send(*args)
        return true
    end
end

class TestTftp < Test::Unit::TestCase
    def test_setup
    end
    
    def test_rrq
        rrq = TftpPacketRRQ.new
        rrq.filename = 'myfilename'
        rrq.mode = 'octet'
        rrq.encode
        assert_equal("\000\001myfilename\000octet\000", rrq.buffer)
        assert_equal(1, rrq.opcode)
        rrq.decode
        assert_equal('myfilename', rrq.filename)
        assert_equal('octet', rrq.mode)
    end
    
    def test_wrq
        wrq = TftpPacketWRQ.new
        wrq.buffer = "\000\002myfilename\000octet\000"
        wrq.decode
        assert_equal('myfilename', wrq.filename)
        assert_equal('octet', wrq.mode)
        assert_equal(2, wrq.opcode)
        wrq.encode.decode
        assert_equal('myfilename', wrq.filename)
        assert_equal('octet', wrq.mode)
        assert_equal(2, wrq.opcode)
    end
    
    def test_dat
        dat = TftpPacketDAT.new
        sampledat = "\000\001\002\003\004\005"
        dat.data = sampledat
        dat.encode.decode
        assert_equal(sampledat, dat.data)
        assert_equal(6, dat.data.length)
        assert_equal(3, dat.opcode)
    end
    
    def test_ack
        ack = TftpPacketACK.new
        ack.blocknumber = 5
        assert_equal(4, ack.opcode)
        assert_equal(5, ack.encode.decode.blocknumber)
    end
    
    def test_err
        err = TftpPacketERR.new
        err.errorcode = 3
        assert_equal('Disk full or allocation exceeded.',
                     err.encode.decode.errmsg)
        assert_equal(5, err.opcode)
    end
    
    def test_oack
        oack = TftpPacketOACK.new
        oack_options = {
            :blksize => 4096
        }
        oack.options = oack_options
        oack.encode.decode
        assert_equal('4096', oack.options[:blksize])
        assert_equal(6, oack.opcode)
    end
    
    def test_errortype
        assert_equal(0, TftpErrorType.notDefined)
        assert_equal(1, TftpErrorType.fileNotFound)
        assert_equal(2, TftpErrorType.accessViolation)
        assert_equal(3, TftpErrorType.diskFull)
        assert_equal(4, TftpErrorType.illegalTftpOp)
        assert_equal(5, TftpErrorType.unknownTID)
        assert_equal(6, TftpErrorType.fileAlreadyExists)
        assert_equal(7, TftpErrorType.noSuchUser)
        assert_equal(8, TftpErrorType.failedNegotiation)
    end
    
    def test_packetfactory
        factory = TftpPacketFactory.new
        rrq = factory.create(1)
        wrq = factory.create(2)
        dat = factory.create(3)
        ack = factory.create(4)
        err = factory.create(5)
        oack = factory.create(6)
        assert_equal(true, rrq.is_a?(TftpPacketRRQ))
        assert_equal(true, wrq.is_a?(TftpPacketWRQ))
        assert_equal(true, dat.is_a?(TftpPacketDAT))
        assert_equal(true, ack.is_a?(TftpPacketACK))
        assert_equal(true, err.is_a?(TftpPacketERR))
        assert_equal(true, oack.is_a?(TftpPacketOACK))
        assert_raise(ArgumentError) { factory.create(0) }
        assert_raise(ArgumentError) { factory.create(7) }
        assert_raise(ArgumentError) { factory.parse(TftpPacketRRQ.new) }
        assert_raise(ArgumentError) { factory.parse(TftpPacketRRQ.new.buffer) }
        assert_raise(TftpError) { factory.parse("foobar") }
    end

    def test_session
        session = TftpSession.new
        assert_equal(512, session.options[:blksize])
        assert_equal(nil, session.state)
        assert_equal(0, session.dups)
        assert_equal(0, session.errors)

        sock = MockSock.new
        assert_equal(true, session.senderror(sock, 1, '192.168.0.1', '69'))
    end
end
