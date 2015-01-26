# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

import unittest

import socket
from tlslite.tlsrecordlayer import TLSRecordLayer
from tlslite.messages import ClientHello, ServerHello, Certificate, \
        ServerHelloDone, ClientKeyExchange, ChangeCipherSpec, Finished, \
        RecordHeader3, ServerKeyExchange
from tlslite.extensions import TLSExtension
from tlslite.constants import ContentType, HandshakeType, CipherSuite, \
        CertificateType
from tlslite.errors import TLSLocalAlert
from tlslite.mathtls import calcMasterSecret, PRF_1_2
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.utils.codec import Parser
from tlslite.utils.cryptomath import bytesToNumber, powMod, numberToByteArray

class TestTLSRecordLayer(unittest.TestCase):
    def test___init__(self):
        record_layer = TLSRecordLayer(None)

        self.assertIsInstance(record_layer, TLSRecordLayer)

    #@unittest.skip("needs external TLS server")
    def test_full_connection_with_external_server_using_DHE(self):

        # TODO test is slow (100ms) move to integration test suite
        #
        # start a regular TLS server locally before running this test
        # e.g.: openssl s_server -key localhost.key -cert localhost.crt

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", 4433))

        record_layer = TLSRecordLayer(sock)

        record_layer._handshakeStart(client=True)
        record_layer.version = (3,3)

        client_hello = ClientHello()
        client_hello = client_hello.create((3,3), bytearray(32),
                bytearray(0), [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA],
                None, None, False, False, None)

        for result in record_layer._sendMsg(client_hello):
            if result in (0,1):
                raise Exception("blocking socket")

        for result in record_layer._getMsg(ContentType.handshake,
                HandshakeType.server_hello):
            if result in (0,1):
                raise Exception("blocking socket")
            else:
                break

        server_hello = result
        self.assertEqual(ServerHello, type(server_hello))

        for result in record_layer._getMsg(ContentType.handshake,
                HandshakeType.certificate, CertificateType.x509):
            if result in (0,1):
                raise Exception("blocking socket")
            else:
                break

        server_certificate = result
        self.assertEqual(Certificate, type(server_certificate))

        for result in record_layer._getMsg(ContentType.handshake,
                HandshakeType.server_key_exchange,
                constructorType=CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA):
            if result in (0,1):
                raise Exception("blocking socket")
            else:
                break

        server_key_exchange = result
        self.assertEqual(ServerKeyExchange, type(server_key_exchange))

        for result in record_layer._getMsg(ContentType.handshake,
                HandshakeType.server_hello_done):
            if result in (0,1):
                raise Exception("blocking socket")
            else:
                break

        server_hello_done = result
        self.assertEqual(ServerHelloDone, type(server_hello_done))

        # verify signature on server kex
        public_key = server_certificate.certChain.getEndEntityPublicKey()

        self.assertTrue(public_key.hashAndVerify(server_key_exchange.signature,
                bytearray(32) + server_hello.random + server_key_exchange.raw_data))

        dh_Xc = bytesToNumber(bytes(b'\x01' + b'\x00' * 31)) # client random
        dh_Yc = powMod(server_key_exchange.dh_g, dh_Xc, server_key_exchange.dh_p)

        client_key_exchange = ClientKeyExchange(
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                (3,3))
        client_key_exchange.createDH(dh_Yc)

        for result in record_layer._sendMsg(client_key_exchange):
            if result in (0,1):
                raise Exception("blocking socket")
            else:
                break

        dh_S = powMod(server_key_exchange.dh_Ys, dh_Xc, server_key_exchange.dh_p)
        premasterSecret = numberToByteArray(dh_S)

        master_secret = calcMasterSecret((3,3), premasterSecret,
                client_hello.random, server_hello.random)

        record_layer._calcPendingStates(
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                master_secret, client_hello.random, server_hello.random,
                None)

        for result in record_layer._sendMsg(ChangeCipherSpec()):
            if result in (0,1):
                raise Exception("blocking socket")
            else:
                break

        record_layer._changeWriteState()

        handshake_hashes = record_layer._handshake_sha256.digest()
        verify_data = PRF_1_2(master_secret, b'client finished',
                handshake_hashes, 12)

        finished = Finished((3,3)).create(verify_data)
        for result in record_layer._sendMsg(finished):
            if result in (0,1):
                raise Exception("blocking socket")
            else:
                break

        for result in record_layer._getMsg(ContentType.change_cipher_spec):
            if result in (0,1):
                raise Exception("blocking socket")
            else:
                break

        change_cipher_spec = result
        self.assertEqual(ChangeCipherSpec, type(change_cipher_spec))

        record_layer._changeReadState()

        handshake_hashes = record_layer._handshake_sha256.digest()
        server_verify_data = PRF_1_2(master_secret, b'server finished',
                handshake_hashes, 12)

        for result in record_layer._getMsg(ContentType.handshake,
                HandshakeType.finished):
            if result in (0,1):
                raise Exception("blocking socket")
            else:
                break

        server_finished = result
        self.assertEqual(Finished, type(server_finished))
        self.assertEqual(server_verify_data, server_finished.verify_data)

        record_layer._handshakeDone(resumed=False)

        record_layer.write(bytearray(b'text\n'))

        record_layer.close()

