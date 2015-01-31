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
from tlslite.utils.cryptomath import bytesToNumber, powMod, numberToByteArray, \
        getRandomSafePrime, getRandomNumber

class TestTLSRecordLayer(unittest.TestCase):
    def test___init__(self):
        record_layer = TLSRecordLayer(None)

        self.assertIsInstance(record_layer, TLSRecordLayer)

    def test_full_connection_with_DHE_kex(self):

        clnt_sock, srv_sock = socket.socketpair()

        #
        # client part
        #

        record_layer = TLSRecordLayer(clnt_sock)

        record_layer._handshakeStart(client=True)
        record_layer.version = (3,3)

        client_hello = ClientHello()
        client_hello = client_hello.create((3,3), bytearray(32),
                bytearray(0), [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA],
                None, None, False, False, None)

        for result in record_layer._sendMsg(client_hello):
            if result in (0,1):
                raise Exception("blocking socket")

        #
        # server part
        #

        srv_record_layer = TLSRecordLayer(srv_sock)
        srv_record_layer = TLSRecordLayer(srv_sock)

        srv_raw_certificate = str(
            "-----BEGIN CERTIFICATE-----\n"\
            "MIIB9jCCAV+gAwIBAgIJAMyn9DpsTG55MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV\n"\
            "BAMMCWxvY2FsaG9zdDAeFw0xNTAxMjExNDQzMDFaFw0xNTAyMjAxNDQzMDFaMBQx\n"\
            "EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA\n"\
            "0QkEeakSyV/LMtTeARdRtX5pdbzVuUuqOIdz3lg7YOyRJ/oyLTPzWXpKxr//t4FP\n"\
            "QvYsSJiVOlPk895FNu6sNF/uJQyQGfFWYKkE6fzFifQ6s9kssskFlL1DVI/dD/Zn\n"\
            "7sgzua2P1SyLJHQTTs1MtMb170/fX2EBPkDz+2kYKN0CAwEAAaNQME4wHQYDVR0O\n"\
            "BBYEFJtvXbRmxRFXYVMOPH/29pXCpGmLMB8GA1UdIwQYMBaAFJtvXbRmxRFXYVMO\n"\
            "PH/29pXCpGmLMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAkOgC7LP/\n"\
            "Rd6uJXY28HlD2K+/hMh1C3SRT855ggiCMiwstTHACGgNM+AZNqt6k8nSfXc6k1gw\n"\
            "5a7SGjzkWzMaZC3ChBeCzt/vIAGlMyXeqTRhjTCdc/ygRv3NPrhUKKsxUYyXRk5v\n"\
            "g/g6MwxzXfQP3IyFu3a9Jia/P89Z1rQCNRY=\n"\
            "-----END CERTIFICATE-----\n"\
            )

        srv_raw_key = str(
            "-----BEGIN RSA PRIVATE KEY-----\n"\
            "MIICXQIBAAKBgQDRCQR5qRLJX8sy1N4BF1G1fml1vNW5S6o4h3PeWDtg7JEn+jIt\n"\
            "M/NZekrGv/+3gU9C9ixImJU6U+Tz3kU27qw0X+4lDJAZ8VZgqQTp/MWJ9Dqz2Syy\n"\
            "yQWUvUNUj90P9mfuyDO5rY/VLIskdBNOzUy0xvXvT99fYQE+QPP7aRgo3QIDAQAB\n"\
            "AoGAVSLbE8HsyN+fHwDbuo4I1Wa7BRz33xQWLBfe9TvyUzOGm0WnkgmKn3LTacdh\n"\
            "GxgrdBZXSun6PVtV8I0im5DxyVaNdi33sp+PIkZU386f1VUqcnYnmgsnsUQEBJQu\n"\
            "fUZmgNM+bfR+Rfli4Mew8lQ0sorZ+d2/5fsM0g80Qhi5M3ECQQDvXeCyrcy0u/HZ\n"\
            "FNjIloyXaAIvavZ6Lc6gfznCSfHc5YwplOY7dIWp8FRRJcyXkA370l5dJ0EXj5Gx\n"\
            "udV9QQ43AkEA34+RxjRk4DT7Zo+tbM/Fkoi7jh1/0hFkU5NDHweJeH/mJseiHtsH\n"\
            "KOcPGtEGBBqT2KNPWVz4Fj19LiUmmjWXiwJBAIBs49O5/+ywMdAAqVblv0S0nweF\n"\
            "4fwne4cM+5ZMSiH0XsEojGY13EkTEon/N8fRmE8VzV85YmkbtFWgmPR85P0CQQCs\n"\
            "elWbN10EZZv3+q1wH7RsYzVgZX3yEhz3JcxJKkVzRCnKjYaUi6MweWN76vvbOq4K\n"\
            "G6Tiawm0Duh/K4ZmvyYVAkBppE5RRQqXiv1KF9bArcAJHvLm0vnHPpf1yIQr5bW6\n"\
            "njBuL4qcxlaKJVGRXT7yFtj2fj0gv3914jY2suWqp8XJ\n"\
            "-----END RSA PRIVATE KEY-----\n"\
            )

        srv_private_key = parsePEMKey(srv_raw_key, private=True)
        srv_cert_chain = X509CertChain([X509().parse(srv_raw_certificate)])

        srv_record_layer._handshakeStart(client=False)

        srv_record_layer.version = (3,3)

        for result in srv_record_layer._getMsg(ContentType.handshake,
                HandshakeType.client_hello):
            if result in (0,1):
                raise Exception("blocking socket")
            else: break

        srv_client_hello = result
        self.assertEqual(ClientHello, type(srv_client_hello))

        srv_cipher_suite = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        srv_session_id = bytearray(0)

        srv_server_hello = ServerHello().create(
                (3,3), bytearray(32), srv_session_id, srv_cipher_suite,
                CertificateType.x509, None, None)

        # XXX bad generation, just to check if rest works
        srv_dh_p = getRandomSafePrime(32, False)
        srv_dh_g = getRandomNumber(2, srv_dh_p)
        srv_dh_Xs = bytesToNumber(bytearray(b'\x01' + b'\x00'*31))
        srv_dh_Ys = powMod(srv_dh_g, srv_dh_Xs, srv_dh_p)

        srv_server_key_exchange = ServerKeyExchange(\
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
        srv_server_key_exchange.createDH(srv_dh_p, srv_dh_g, srv_dh_Ys)
        srv_server_key_exchange.sign(srv_client_hello.random,
                srv_server_hello.random, srv_private_key)

        srv_msgs = []
        srv_msgs.append(srv_server_hello)
        srv_msgs.append(Certificate(CertificateType.x509).create(
            srv_cert_chain))
        srv_msgs.append(srv_server_key_exchange)
        srv_msgs.append(ServerHelloDone())
        for result in srv_record_layer._sendMsgs(srv_msgs):
            if result in (0,1):
                raise Exception("Blocking socket")
            else: break
        srv_record_layer._versionCheck = True

        #
        # client part
        #

        for result in record_layer._getMsg(ContentType.handshake,
                HandshakeType.server_hello):
            if result in (0,1):
                raise Exception("blocking socket")
            else:
                break

        server_hello = result
        self.assertEqual(ServerHello, type(server_hello))
        self.assertEqual(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                server_hello.cipher_suite)

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

        dh_Xc = bytesToNumber(bytearray(b'\x01' + b'\x00' * 31)) # client random
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

        # same cipher suite, just with different kex to make it a bit easier
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

        #
        # server part
        #

        for result in srv_record_layer._getMsg(ContentType.handshake,
                HandshakeType.client_key_exchange,
                srv_cipher_suite):
            if result in (0,1):
                raise Exception("blocking socket")
            else: break

        srv_client_key_exchange = result

        srv_dh_Yc = srv_client_key_exchange.dh_Yc

        #sanity check
        if srv_dh_Yc % srv_dh_p == 0:
            assert(False)

        S = powMod(srv_dh_Yc, srv_dh_Xs, srv_dh_p)
        srv_premaster_secret = numberToByteArray(S)

        srv_master_secret = calcMasterSecret(srv_record_layer.version,
                srv_premaster_secret, srv_client_hello.random,
                srv_server_hello.random)

        # XXX that's a wrong cipher suite, temporary to make it easier
        srv_record_layer._calcPendingStates(\
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                srv_master_secret, srv_client_hello.random,
                srv_server_hello.random, None)

        for result in srv_record_layer._getMsg(ContentType.change_cipher_spec):
            if result in (0,1):
                raise Exception("blocking socket")
            else: break

        srv_change_cipher_spec = result

        self.assertEqual(ChangeCipherSpec, type(srv_change_cipher_spec))

        srv_record_layer._changeReadState()

        srv_handshakeHashes = srv_record_layer._handshake_sha256.digest()
        srv_verify_data = PRF_1_2(srv_master_secret, b"client finished",
                srv_handshakeHashes, 12)

        for result in srv_record_layer._getMsg(ContentType.handshake,
                HandshakeType.finished):
            if result in (0,1):
                raise Exception("blocking socket")
            else: break

        srv_finished = result
        self.assertEqual(Finished, type(srv_finished))
        self.assertEqual(srv_verify_data, srv_finished.verify_data)

        for result in srv_record_layer._sendMsg(ChangeCipherSpec()):
            if result in (0,1):
                raise Exception("blocking socket")
            else: break

        srv_record_layer._changeWriteState()

        srv_handshakeHashes = srv_record_layer._handshake_sha256.digest()
        srv_verify_data = PRF_1_2(srv_master_secret, b"server finished",
                srv_handshakeHashes, 12)

        for result in srv_record_layer._sendMsg(Finished((3,3)).create(
            srv_verify_data)):
            if result in (0,1):
                raise Exception("blocking socket")
            else: break

        srv_record_layer._handshakeDone(resumed=False)

        #
        # client part
        #

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

        #
        # server part
        #

        d = srv_record_layer.read(10)
        self.assertEqual(d, bytearray(b'text\n'))

        #
        # client part
        #

        record_layer.close()

        #
        # server part
        #

        srv_record_layer.close()


    @unittest.skip("needs external TLS server")
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

        # same cipher suite but with different kex to make it a bit easier
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

