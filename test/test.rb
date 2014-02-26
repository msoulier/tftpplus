#!/usr/bin/env ruby

$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'net/tftp+'
require 'test/unit'

class TestTftp < Test::Unit::TestCase
    def test_simple
        rrq = TftpPacketRRQ.new
        rrq.filename = 'myfilename'
        rrq.mode = 'octet'
        rrq.encode
        assert_equal("\000\001myfilename\000octet\000", rrq.buffer)
        assert_equal(1, rrq.opcode)

        wrq = TftpPacketWRQ.new
        wrq.buffer = "\000\002myfilename\000octet\000"
        wrq.decode
        assert_equal('myfilename', wrq.filename)
        assert_equal('octet', wrq.mode)
        assert_equal(2, wrq.opcode)

        dat = TftpPacketDAT.new
        sampledat = "\000\001\002\003\004\005"
        dat.data = sampledat
        dat.encode
        assert_equal(sampledat, dat.decode.data)
        assert_equal(6, dat.data.length)
        assert_equal(3, dat.opcode)

        ack = TftpPacketACK.new
        ack.blocknumber = 5
        assert_equal(4, ack.opcode)
        assert_equal(5, ack.encode.decode.blocknumber)

        err = TftpPacketERR.new
        err.errorcode = 3
        assert_equal('Disk full or allocation exceeded.',
                     err.encode.decode.errmsg)
        assert_equal(5, err.opcode)

        oack = TftpPacketOACK.new
        oack_options = {
            :blksize => 4096
        }
        oack.options = oack_options
        oack.encode.decode
        assert_equal(4096, oack.options[:blksize])
        assert_equal(6, oack.opcode)
    end
end
