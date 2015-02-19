# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

import unittest
try:
    import mock
    from mock import call
except ImportError:
    import unittest.mock as mock
    from unittest.mock import call

import sys
import socket
import tlslite.tlsconnection
from tlslite.tlsconnection import TLSConnection
from tlslite.errors import TLSClosedConnectionError
from tlslite.constants import CipherSuite
from unit_tests.mocksock import MockSocket

class TestTLSConnection(unittest.TestCase):
    def test___init__(self):
        conn = TLSConnection(None)

        self.assertIsNotNone(conn)

    def test_getpeername(self):
        mock_sock = mock.create_autospec(socket.socket)

        conn = TLSConnection(mock_sock)

        conn.getpeername()

        self.assertEqual(1, mock_sock.getpeername.call_count)

    def test_getsockname(self):
        mock_sock = mock.create_autospec(socket.socket)

        conn = TLSConnection(mock_sock)

        conn.getsockname()

        self.assertEqual(1, mock_sock.getsockname.call_count)

    def test_gettimeout(self):
        mock_sock = mock.create_autospec(socket.socket)

        conn = TLSConnection(mock_sock)

        conn.gettimeout()

        self.assertEqual(1, mock_sock.gettimeout.call_count)

    def test_makefile(self):
        conn = TLSConnection(None)

        if sys.version_info < (3,):
            with mock.patch.object(socket, '_fileobject', return_value=11)\
                    as mock_method:
                conn.makefile(mode='r')

            self.assertEqual(1, mock_method.call_count)
            self.assertEqual(mock.call(conn, 'r', -1, close=True),
                    mock_method.call_args)
        else:
            with mock.patch.object(socket, 'SocketIO', return_value=11)\
                    as mock_method:
                conn.makefile(mode='r')

            self.assertEqual(1, mock_method.call_count)
            self.assertEqual(mock.call(conn, 'r'), mock_method.call_args)

    def test_setsockopt(self):
        mock_sock = mock.create_autospec(socket.socket)

        conn = TLSConnection(mock_sock)

        conn.setsockopt(44, 73, 33)

        self.assertEqual(1, mock_sock.setsockopt.call_count)
        self.assertEqual(mock.call(44, 73, 33), mock_sock.setsockopt.call_args)

    def test_settimeout(self):
        mock_sock = mock.create_autospec(socket.socket)

        conn = TLSConnection(mock_sock)

        conn.settimeout(1012)

        self.assertEqual(1, mock_sock.settimeout.call_count)
        self.assertEqual(mock.call(1012), mock_sock.settimeout.call_args)

    def test_shutdown(self):
        mock_sock = mock.create_autospec(socket.socket)

        conn = TLSConnection(mock_sock)

        conn.shutdown('rw')

        self.assertEqual(1, mock_sock.shutdown.call_count)
        self.assertEqual(mock.call('rw'), mock_sock.shutdown.call_args)

    def test_close(self):
        mock_sock = MockSocket(bytearray(0))

        record_layer = TLSConnection(mock_sock)
        record_layer.closed = False
        record_layer._refCount = 1

        record_layer.close()
        self.assertEqual([bytearray(
            b'\x15' +           # type - alert
            b'\x00\x00' +       # version
            b'\x00\x02' +       # length
            b'\x01' +           # alert level - warning
            b'\x00'             # alert description - close_notify
            )], mock_sock.sent)

    def test_closeAsync(self):
        mock_sock = MockSocket(bytearray(0))
        record_layer = TLSConnection(mock_sock)
        record_layer.closed = False
        record_layer._refCount = 1

        for result in record_layer.closeAsync():
            if result in (0, 1):
                raise Exception("blocked write")
            else:
                raise Exception("returned data")

        self.assertEqual([bytearray(
            b'\x15' +           # type - alert
            b'\x00\x00' +       # version
            b'\x00\x02' +       # length
            b'\x01' +           # alert level - warning
            b'\x00'             # alert description - close_notify
            )], mock_sock.sent)

    def test_fileno(self):
        conn = TLSConnection(None)

        with self.assertRaises(NotImplementedError):
            conn.fileno()

    def test_readAsync(self):
        mock_sock = MockSocket(bytearray(\
                b'\x17' +           # content type - application data
                b'\x03\x03' +       # TLSv1.2
                b'\x00\x04' +       # length
                b'text'
                ))

        record_layer = TLSConnection(mock_sock)
        record_layer.closed = False

        for result in record_layer.readAsync(4):
            if result in (0, 1):
                raise Exception("blocked read")
            else: break

        self.assertEqual(result, b'text')

        # socket is empty so it should return "retry needed"
        self.assertEqual(0, next(record_layer.readAsync(4)))

    def test_write_with_open_socket(self):
        mock_sock = MockSocket(bytearray(0))

        record_layer = TLSConnection(mock_sock)
        record_layer.closed = False

        record_layer.write(b'text')

        self.assertEqual([bytearray(
            b'\x17' +           # content type - application data
            b'\x00\x00' +       # version - uninitialised
            b'\x00\x04' +       # length
            b'text')], mock_sock.sent)

    def test_write(self):
        mock_sock = MockSocket(bytearray(0))

        record_layer = TLSConnection(mock_sock)

        with self.assertRaises(TLSClosedConnectionError):
            record_layer.write('text')

    def test_writeAsync(self):
        mock_sock = MockSocket(bytearray(0))

        record_layer = TLSConnection(mock_sock)
        record_layer.closed = False

        for result in record_layer.writeAsync(b'text'):
            if result in (0, 1):
                raise Exception("Blocking write")
            else:
                raise Exception("result returned")

        self.assertEqual([bytearray(
            b'\x17' +           # content type - application data
            b'\x00\x00' +       # version - uninitialised
            b'\x00\x04' +       # length
            b'text')], mock_sock.sent)

    def test_send(self):
        mock_sock = MockSocket(bytearray(0))

        record_layer = TLSConnection(mock_sock)
        record_layer.closed = False

        record_layer.send(b'text')

        self.assertEqual([bytearray(
            b'\x17' +           # content type - application data
            b'\x00\x00' +       # version - uninitialised
            b'\x00\x04' +       # length
            b'text')], mock_sock.sent)

    def test_sendall(self):
        mock_sock = MockSocket(bytearray(0))

        record_layer = TLSConnection(mock_sock)
        record_layer.closed = False

        record_layer.sendall(b'text')

        self.assertEqual([bytearray(
            b'\x17' +           # content type - application data
            b'\x00\x00' +       # version - uninitialised
            b'\x00\x04' +       # length
            b'text')], mock_sock.sent)

    def test_unread(self):
        mock_sock = MockSocket(bytearray(\
                b'\x17' +           # content type - application data
                b'\x03\x03' +       # TLSv1.2
                b'\x00\x04' +       # length
                b'text'
                ))

        record_layer = TLSConnection(mock_sock)
        record_layer.closed = False

        record_layer.unread(b'some')

        self.assertEqual(b'some', record_layer.read(8))
        self.assertEqual(b'text', record_layer.read(8))

    def teat_unread_with_closed_socket(self):
        mock_sock = MockSocket(bytearray(0))

        conn = TLSConnection(mock_sock)
        conn.unread(bytearray(b'text'))

        self.assertEqual(bytearray(b'text'), conn.read(10))

    def test_recv(self):
        mock_sock = MockSocket(bytearray(\
                b'\x17' +           # content type - application data
                b'\x03\x03' +       # TLSv1.2
                b'\x00\x04' +       # length
                b'text'
                ))

        record_layer = TLSConnection(mock_sock)
        record_layer.closed = False

        res = record_layer.recv(4)

        self.assertEqual(res, b'text')

    def test_recv_into(self):
        mock_sock = MockSocket(bytearray(\
                b'\x17' +           # content type - application data
                b'\x03\x03' +       # TLSv1.2
                b'\x00\x04' +       # length
                b'text'
                ))

        record_layer = TLSConnection(mock_sock)
        record_layer.closed = False

        b = bytearray(6)

        res = record_layer.recv_into(b)

        self.assertEqual(res, 4)
        self.assertEqual(bytearray(b'text\x00\x00'), b)

    def test_read_with_unencrypted_data(self):
        mock_sock = MockSocket(bytearray(\
                b'\x17' +           # content type - application data
                b'\x03\x03' +       # TLSv1.2
                b'\x00\x04' +       # length
                b'text'
                ))

        record_layer = TLSConnection(mock_sock)
        record_layer.closed = False

        res = record_layer.read(4)

        self.assertEqual(res, b'text')

    def test_read_with_empty_socket(self):
        mock_sock = MockSocket(bytearray(0))

        record_layer = TLSConnection(mock_sock)

        res = record_layer.read(2)

        self.assertEqual(res, b'')

    def test_read_with_closed_socket(self):
        mock_sock = MockSocket(bytearray(\
                b'\x17' +           # content type - application data
                b'\x03\x03' +       # TLSv1.2
                b'\x00\x04' +       # length
                b'text'
                ))

        record_layer = TLSConnection(mock_sock)

        res = record_layer.read(4)

        # read from "closed" socket
        self.assertEqual(res, b'')

    def test_getCipherName(self):
        record_layer = TLSConnection(None)

        self.assertEqual(None, record_layer.getCipherName())

    def test_getCipherName_with_initialised_context(self):
        record_layer = TLSConnection(None)
        record_layer.version = (3, 0)

        record_layer._calcPendingStates(
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                bytearray(48), bytearray(32), bytearray(32), None)

        record_layer._changeWriteState()

        self.assertEqual('aes128', record_layer.getCipherName())

    def test_getCipherImplementation(self):
        record_layer = TLSConnection(None)

        self.assertEqual(None, record_layer.getCipherImplementation())

    def test_getCipherImplementation_with_initialised_context(self):
        record_layer = TLSConnection(None)
        record_layer.version = (3, 0)

        record_layer._calcPendingStates(
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                bytearray(48), bytearray(32), bytearray(32), None)

        record_layer._changeWriteState()

        if tlslite.tlsconnection.m2cryptoLoaded:
            self.assertEqual('openssl', record_layer.getCipherImplementation())
        else:
            self.assertEqual('python', record_layer.getCipherImplementation())

    def test_getVersionName_with_SSL3(self):
        record_layer = TLSConnection(None)
        record_layer.version = (3, 0)

        self.assertEqual('SSL 3.0', record_layer.getVersionName())

    def test_getVersionName_with_TLS10(self):
        record_layer = TLSConnection(None)
        record_layer.version = (3, 1)

        self.assertEqual('TLS 1.0', record_layer.getVersionName())

    def test_getVersionName_with_TLS11(self):
        record_layer = TLSConnection(None)
        record_layer.version = (3, 2)

        self.assertEqual('TLS 1.1', record_layer.getVersionName())

    def test_getVersionName_with_TLS12(self):
        record_layer = TLSConnection(None)
        record_layer.version = (3, 3)

        self.assertEqual('TLS 1.2', record_layer.getVersionName())

    def test_clearReadBuffer(self):
        sock = MockSocket(bytearray(0))
        connection = TLSConnection(sock)
        connection.unread(bytearray(b'test'))

        connection.clearReadBuffer()

        res = connection.read(10)
        self.assertEqual(res, bytearray(0))

    def test_clearWriteBuffer(self):
        conn = TLSConnection(None)

        # operation is effectively no-op, but the function has to exist
        # and not throw an exception
        conn.clearWriteBuffer()
