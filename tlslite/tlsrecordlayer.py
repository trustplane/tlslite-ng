# Authors:
#   Trevor Perrin
#   Google (adapted by Sam Rushing) - NPN support
#   Martin von Loewis - python 3 port
#   Yngve Pettersen (ported by Paul Sokolovsky) - TLS 1.2
#   Hubert Kario - Encrypt then MAC - RFC 7366
#
# See the LICENSE file for legal information regarding use of this file.

"""Helper class for TLSConnection."""
from __future__ import generators

from .utils.compat import *
from .utils.cryptomath import *
from .utils.cipherfactory import createAES, createRC4, createTripleDES
from .utils.codec import *
from .errors import *
from .messages import *
from .mathtls import *
from .constants import *
from .utils.cryptomath import getRandomBytes
from .handshakehashes import HandshakeHashes

import socket
import errno
import traceback

class _ConnectionState(object):
    def __init__(self):
        self.macContext = None
        self.encContext = None
        self.seqnum = 0

    def getSeqNumBytes(self):
        w = Writer()
        w.add(self.seqnum, 8)
        self.seqnum += 1
        return w.bytes


class TLSRecordLayer(object):
    """
    This class handles data transmission for a TLS connection.

    Its only subclass is L{tlslite.TLSConnection.TLSConnection}.  We've
    separated the code in this class from TLSConnection to make things
    more readable.


    @type sock: socket.socket
    @ivar sock: The underlying socket object.

    @type session: L{tlslite.Session.Session}
    @ivar session: The session corresponding to this connection.

    Due to TLS session resumption, multiple connections can correspond
    to the same underlying session.

    @type version: tuple
    @ivar version: The TLS version being used for this connection.

    (3,0) means SSL 3.0, and (3,1) means TLS 1.0.

    @type closed: bool
    @ivar closed: If this connection is closed to writing application_data,
    there still may be some leftover messages in buffer to read.

    @type closeSocket: bool
    @ivar closeSocket: If the socket should be closed when the
    connection is closed, defaults to True (writable).

    If you set this to True, TLS Lite will assume the responsibility of
    closing the socket when the TLS Connection is shutdown (either
    through an error or through the user calling close()).  The default
    is False.

    @type ignoreAbruptClose: bool
    @ivar ignoreAbruptClose: If an abrupt close of the socket should
    raise an error (writable).

    If you set this to True, TLS Lite will not raise a
    L{tlslite.errors.TLSAbruptCloseError} exception if the underlying
    socket is unexpectedly closed.  Such an unexpected closure could be
    caused by an attacker.  However, it also occurs with some incorrect
    TLS implementations.

    You should set this to True only if you're not worried about an
    attacker truncating the connection, and only if necessary to avoid
    spurious errors.  The default is False.

    @type etm: bool
    @ivar etm: if the record layer uses encrypt-then-mac construct defined
    in RFC 7366 (read only)

    @type blockSize: int
    @ivar blockSize: maximum size of data to be sent in a single record
    layer message. Note that after encryption is established (generally
    after handshake protocol has finished) the actual amount of data written
    to network socket will be larger because of the record layer header,
    padding, or encryption overhead. It can be set to low value (so that
    there is not fragmentation on Ethernet, IP and TCP level) at the
    beginning of connection to reduce latency and set to protocol max (2**14)
    to maximise throughput after sending few kiB of data. Setting to values
    greater than 2**14 (16384) will cause the connection to be dropped by
    RFC compliant peers.

    @type client: bool
    @ivar client: variable notifying the record layer if it has to behave
    as a client or a server side of connection.

    @sort: __init__, getCipherImplementation, getCipherName
    """

    def __init__(self, sock):
        self.sock = sock

        #My session object (Session instance; read-only)
        self.session = None

        #Am I a client or server?
        self.client = None

        #Buffers for processing messages
        self._handshakeBuffer = bytearray(0)
        self._handshakeRecord = None

        #TLS Protocol Version
        self.version = (0,0) #read-only
        self._versionCheck = False #Once we choose a version, this is True

        #Current and Pending connection states
        self._writeState = _ConnectionState()
        self._readState = _ConnectionState()
        self._pendingWriteState = _ConnectionState()
        self._pendingReadState = _ConnectionState()

        #Is the connection open?
        self.closed = True #read-only

        #On a call to close(), do we close the socket? (writeable)
        self.closeSocket = True

        #If the socket is abruptly closed, do we ignore it
        #and pretend the connection was shut down properly? (writeable)
        self.ignoreAbruptClose = False

        #Fault we will induce, for testing purposes
        self.fault = None

        #Limit the size of outgoing records to following size
        self.blockSize = 16384 # 2**14

        #Whatever to do Encrypt and MAC or MAC and Encrypt
        self.etm = False


    #*********************************************************
    # Public Functions START
    #*********************************************************

    def getVersionName(self):
        """Get the name of this TLS version.

        @rtype: str
        @return: The name of the TLS version used with this connection.
        Either None, 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', or 'TLS 1.2'.
        """
        if self.version == (3,0):
            return "SSL 3.0"
        elif self.version == (3,1):
            return "TLS 1.0"
        elif self.version == (3,2):
            return "TLS 1.1"
        elif self.version == (3,3):
            return "TLS 1.2"
        else:
            return None

    def getCipherName(self):
        """Get the name of the cipher used with this connection.

        @rtype: str
        @return: The name of the cipher used with this connection.
        Either 'aes128', 'aes256', 'rc4', or '3des'.
        """
        if not self._writeState.encContext:
            return None
        return self._writeState.encContext.name

    def getCipherImplementation(self):
        """Get the name of the cipher implementation used with
        this connection.

        @rtype: str
        @return: The name of the cipher implementation used with
        this connection.  Either 'python', 'openssl', or 'pycrypto'.
        """
        if not self._writeState.encContext:
            return None
        return self._writeState.encContext.implementation




     #*********************************************************
     # Public Functions END
     #*********************************************************

    def _shutdown(self, resumable):
        self._writeState = _ConnectionState()
        self._readState = _ConnectionState()
        self.version = (0,0)
        self._versionCheck = False
        self.closed = True
        if self.closeSocket:
            self.sock.close()

        #Even if resumable is False, we'll never toggle this on
        if not resumable and self.session:
            self.session.resumable = False


    def _sendError(self, alertDescription, errorStr=None):
        alert = Alert().create(alertDescription, AlertLevel.fatal)
        for result in self.sendMessage(alert):
            yield result
        self._shutdown(False)
        raise TLSLocalAlert(alert, errorStr)

    def sendMessages(self, msgs):
        randomizeFirstBlock = True
        for msg in msgs:
            for result in self.sendMessage(msg, randomizeFirstBlock):
                yield result
            randomizeFirstBlock = True

    def sendMessage(self, msg, randomizeFirstBlock = True):
        """
        Generator which will try to fragment, encrypt and then send
        a message.

        @type msg: Alert, HandshakeMsg or ApplicationData
        @param msg: message to send
        @rtype: generator
        @return: generator that will finish if the sending was successful or
        0 or 1 if the read or write to socket would block.
        """
        #Whenever we're connected and asked to send an app data message,
        #we first send the first byte of the message.  This prevents
        #an attacker from launching a chosen-plaintext attack based on
        #knowing the next IV (a la BEAST).
        if not self.closed and randomizeFirstBlock and self.version <= (3,1) \
                and self._writeState.encContext \
                and self._writeState.encContext.isBlockCipher \
                and isinstance(msg, ApplicationData):
            msgFirstByte = msg.splitFirstByte()
            for result in self.sendMessage(msgFirstByte,
                                       randomizeFirstBlock = False):
                yield result

        b = msg.write()

        # If a 1-byte message was passed in, and we "split" the
        # first(only) byte off above, we may have a 0-length msg:
        if len(b) == 0:
            return

        contentType = msg.contentType

        #Fragment big messages
        while len(b) > self.blockSize:
            newB = b[:self.blockSize]
            b = b[self.blockSize:]

            class FakeMsg(object):
                def __init__(self, msg_type, data):
                    self.contentType = msg_type
                    self.data = data

                def write(self):
                    return self.data

            msgFragment = FakeMsg(msg.contentType, newB)
            for result in self.sendMessage(msgFragment,
                    randomizeFirstBlock=False):
                yield result

        if self.etm:
            b = self._encryptThenMAC(b, contentType)
        else:
            b = self._macThenEncrypt(b, contentType)

        #Add record header and send
        r = RecordHeader3().create(self.version, contentType, len(b))
        s = r.write() + b
        while 1:
            try:
                bytesSent = self.sock.send(s) #Might raise socket.error
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 1
                    continue
                else:
                    # The socket was unexpectedly closed.  The tricky part
                    # is that there may be an alert sent by the other party
                    # sitting in the read buffer.  So, if we get here after
                    # handshaking, we will just raise the error and let the
                    # caller read more data if it would like, thus stumbling
                    # upon the error.
                    #
                    # However, if we get here DURING handshaking, we take
                    # it upon ourselves to see if the next message is an 
                    # Alert.
                    if contentType == ContentType.handshake:
                        
                        # See if there's an alert record
                        # Could raise socket.error or TLSAbruptCloseError
                        for result in self.recvMessage():
                            if result in (0,1):
                                yield result
                                
                        # Closes the socket
                        self._shutdown(False)
                        
                        # If we got an alert, raise it        
                        recordHeader, p = result                        
                        if recordHeader.type == ContentType.alert:
                            alert = Alert().parse(p)
                            raise TLSRemoteAlert(alert)
                    else:
                        # If we got some other message who know what
                        # the remote side is doing, just go ahead and
                        # raise the socket.error
                        raise
            if bytesSent == len(s):
                return
            s = s[bytesSent:]
            yield 1

    def _encryptThenMAC(self, b, contentType):
        # add padding and encrypt
        if self._writeState.encContext:
            # add IV for TLS1.1+
            if self.version >= (3,2):
                b = self.fixedIVBlock + b

            # add padding
            currentLength = len(b) + 1
            blockLength = self._writeState.encContext.block_size
            paddingLength = blockLength - (currentLength % blockLength)

            paddingBytes = bytearray([paddingLength] * (paddingLength + 1))
            b += paddingBytes

            # encrypt
            b = self._writeState.encContext.encrypt(b)

        # add MAC
        if self._writeState.macContext:
            # calculate HMAC
            seqnumBytes = self._writeState.getSeqNumBytes()
            mac = self._writeState.macContext.copy()
            mac.update(compatHMAC(seqnumBytes))
            mac.update(compatHMAC(bytearray([contentType])))
            mac.update(compatHMAC(bytearray([self.version[0]])))
            mac.update(compatHMAC(bytearray([self.version[1]])))
            mac.update(compatHMAC(bytearray([len(b)//256])))
            mac.update(compatHMAC(bytearray([len(b)%256])))
            mac.update(compatHMAC(b))

            # add HMAC
            macBytes = bytearray(mac.digest())
            b += macBytes

        return b

    def _macThenEncrypt(self, b, contentType):
        #Calculate MAC
        if self._writeState.macContext:
            seqnumBytes = self._writeState.getSeqNumBytes()
            mac = self._writeState.macContext.copy()
            mac.update(compatHMAC(seqnumBytes))
            mac.update(compatHMAC(bytearray([contentType])))
            if self.version == (3,0):
                mac.update( compatHMAC( bytearray([len(b)//256] )))
                mac.update( compatHMAC( bytearray([len(b)%256] )))
            elif self.version in ((3,1), (3,2), (3,3)):
                mac.update(compatHMAC( bytearray([self.version[0]] )))
                mac.update(compatHMAC( bytearray([self.version[1]] )))
                mac.update( compatHMAC( bytearray([len(b)//256] )))
                mac.update( compatHMAC( bytearray([len(b)%256] )))
            else:
                raise AssertionError()
            mac.update(compatHMAC(b))
            macBytes = bytearray(mac.digest())
            if self.fault == Fault.badMAC:
                macBytes[0] = (macBytes[0]+1) % 256

        #Encrypt for Block or Stream Cipher
        if self._writeState.encContext:
            #Add padding and encrypt (for Block Cipher):
            if self._writeState.encContext.isBlockCipher:

                #Add TLS 1.1 fixed block
                if self.version >= (3,2):
                    b = self.fixedIVBlock + b

                #Add padding: b = b+ (macBytes + paddingBytes)
                currentLength = len(b) + len(macBytes) + 1
                blockLength = self._writeState.encContext.block_size
                paddingLength = blockLength-(currentLength % blockLength)

                paddingBytes = bytearray([paddingLength] * (paddingLength+1))
                if self.fault == Fault.badPadding:
                    paddingBytes[0] = (paddingBytes[0]+1) % 256
                endBytes = macBytes + paddingBytes
                b += endBytes
                #Encrypt
                b = self._writeState.encContext.encrypt(b)

            #Encrypt (for Stream Cipher)
            else:
                b += macBytes
                b = self._writeState.encContext.encrypt(b)

        return b

    def _sockRecvAll(self, length):
        """
        Read exactly the amount of bytes specified in L{length} from raw socket.

        @rtype: generator
        @return: generator that will return 0 or 1 in case the socket is non
           blocking and would block and bytearray in case the read finished
        @raise tlslite.errors.TLSAbruptCloseError: when the socket closed
        """

        b = bytearray(0)

        if length == 0:
            yield b
            return

        while 1:
            try:
                s = self.sock.recv(length - len(b))
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 0
                    continue
                else:
                    raise

            #if the connection closed, raise socket error
            if len(s) == 0:
                raise TLSAbruptCloseError()

            b += bytearray(s)
            if len(b) == length:
                yield b
                return

    def _sockRecvRecord(self):
        """
        Read a single record from socket, handles both SSLv2 and SSLv3 record
        layer

        @rtype: generator
        @return: generator that returns 0 or 1 in case the read would be
            blocking or a tuple containing record header (object) and record
            data (bytearray) read from socket
        """

        #Read the next record header
        b = bytearray(0)
        ssl2 = False
        for result in self._sockRecvAll(1):
            if result in (0,1): yield result
            else: break
        b += result

        if b[0] in ContentType.all:
            ssl2 = False
            # SSLv3 record layer header is 5 bytes long, we already read 1
            for result in self._sockRecvAll(4):
                if result in (0,1): yield result
                else: break
            b += result
        # XXX this should be 'b[0] & 128', otherwise hello messages longer than
        # 127 bytes won't be properly parsed
        elif b[0] == 128:
            ssl2 = True
            # in SSLv2 we need to read 2 bytes in total to know the size of
            # header, we already read 1
            for result in self._sockRecvAll(1):
                if result in (0,1): yield result
                else: break
            b += result
        else:
            raise SyntaxError()

        #Parse the record header
        if ssl2:
            r = RecordHeader2().parse(Parser(b))
        else:
            r = RecordHeader3().parse(Parser(b))

        #Check the record header fields
        # 18432 = 2**14 (basic record size limit) + 1024 (maximum compression
        # overhead) + 1024 (maximum encryption overhead)
        if r.length > 18432:
            for result in self._sendError(AlertDescription.record_overflow):
                yield result

        #Read the record contents
        b = bytearray(0)
        for result in self._sockRecvAll(r.length):
            if result in (0,1): yield result
            else: break
        b += result

        yield (r, b)

    def _getHandshakeFromBuffer(self):
        """
        Return generator that tries to read subsequent handshake messages
        from buffer.

        @rtype: generator
        """
        # the handshake messages header is 4 bytes long
        while len(self._handshakeBuffer) >= 4:
            p = Parser(self._handshakeBuffer)
            # skip type
            p.get(1)
            msgLength = p.get(3)
            if p.getRemainingLength() >= msgLength:
                handshakePair = (self._handshakeRecord,
                    Parser(self._handshakeBuffer[:msgLength+4]))
                self._handshakeBuffer = self._handshakeBuffer[msgLength+4:]
                yield handshakePair
            else:
                break

    #Returns next record or next handshake message
    def recvMessage(self):
        """
        Generator which will try to read, decrypt and reassemble messages from
        records read from socket. The returned messages are returned in order
        of the *last* byte of the message received.

        For example, if the record layer recieves records that decrypt to:
        handshake(first 3 bytes), application data, handshake(rest) the
        generator will return twice, once with application data and once
        with handshake message.

        @rtype: generator
        @return: generator which returns tuples of L{RecordLayer3} or
        L{RecordLayer2} and L{Parser} with read message ready for parsing
        """

        # XXX a bit hackish but needed to support fragmentation
        # (RFC 5246 Section 6.2.1)
        # Because the Record Layer is completely separate from the messages
        # that traverse it it should handle both application data and hadshake
        # data in the same way. For that we buffer the handshake messages
        # until they are completely read.
        # This makes it possible to handle both handshake data not aligned to
        # record boundary as well as handshakes longer than single record.

        while True:

            #check if we don't have a message ready in buffer
            for result in self._getHandshakeFromBuffer():
                yield result

            #Otherwise...
            #read the next record
            for result in self._sockRecvRecord():
                if result in (0,1): yield result
                else: break

            r, b = result

            #Check the record header fields (2)
            #We do this after reading the contents from the socket, so that
            #if there's an error, we at least don't leave extra bytes in the
            #socket..
            #
            # THIS CHECK HAS NO SECURITY RELEVANCE (?), BUT COULD HURT INTEROP.
            # SO WE LEAVE IT OUT FOR NOW.
            #
            #if self._versionCheck and r.version != self.version:
            #    for result in self._sendError(AlertDescription.protocol_version,
            #            "Version in header field: %s, should be %s" % (str(r.version),
            #                                                       str(self.version))):
            #        yield result

            #Decrypt the record
            for result in self._decryptRecord(r.type, b):
                if result in (0,1): yield result
                else: break

            # the maximum payload length is 2**14 (2**14+1024 if the record is
            # compressed but tlslite doesn't support compression)
            if len(result) > 2**14:
                for result in self._sendError(AlertDescription.record_overflow):
                    yield result

            b = result
            p = Parser(b)

            #If it doesn't contain handshake messages, we can just return it
            if r.type != ContentType.handshake:
                yield (r, p)
            #If it's an SSLv2 ClientHello, we can return it as well
            elif r.ssl2:
                yield (r, p)
            else:
                assert(r.type == ContentType.handshake)

                # RFC5246 section 5.2.1: Implementations MUST NOT send
                # zero-length fragments of Handshake [...] content types.
                if len(b) == 0:
                    for result in self._sendError(\
                            AlertDescription.decode_error, \
                            "Received empty handshake record"):
                        yield result
                    return

                self._handshakeBuffer += b
                self._handshakeRecord = r

    def _decryptRecord(self, recordType, b):
        if self._readState.encContext:

            if self.etm:
                for result in self._decryptRecordWithEtM(recordType, b):
                    yield result
            else:
                for result in self._decryptRecordWithMtE(recordType, b):
                    yield result
        else:
            yield b

    def _decryptRecordWithEtM(self, recordType, b):
        # check MAC
        macLength = self._readState.macContext.digest_size
        if len(b) < macLength:
            for result in self._sendError(AlertDescription.bad_record_mac,
                    "MAC failure (truncated data)"):
                yield result

        checkBytes = b[-macLength:]
        b = b[:-macLength]

        seqnumBytes = self._readState.getSeqNumBytes()
        mac = self._readState.macContext.copy()
        mac.update(compatHMAC(seqnumBytes))
        mac.update(compatHMAC(bytearray([recordType])))
        mac.update(compatHMAC(bytearray([self.version[0]])))
        mac.update(compatHMAC(bytearray([self.version[1]])))
        mac.update(compatHMAC(bytearray([len(b)//256])))
        mac.update(compatHMAC(bytearray([len(b)%256])))
        mac.update(compatHMAC(b))

        macBytes = bytearray(mac.digest())
        if macBytes != checkBytes:
            for result in self._sendError(AlertDescription.bad_record_mac,
                    "MAC failure (mismatched data)"):
                yield result

        # decrypt
        blockLength = self._readState.encContext.block_size
        if len(b) % blockLength != 0:
            for result in self._sendError(AlertDescription.decryption_failed,
                    "Encrypted data must be multiple of blocksize"):
                yield result

        b = self._readState.encContext.decrypt(b)
        if self.version >= (3,2): # remove explicit IV
            b = b[self._readState.encContext.block_size:]

        # Check padding
        paddingGood = True
        paddingLength = b[-1]
        if (paddingLength+1) > len(b):
            paddingGood = False
            totalPaddingLength = 0
        else:
            if self.version == (3,0):
                totalPaddingLength = paddingLength+1
            else:
                totalPaddingLength = paddingLength+1
                paddingBytes = b[-totalPaddingLength:-1]
                for byte in paddingBytes:
                    if byte != paddingLength:
                        paddingGood = False
                        totalPaddingLength = 0

        if not paddingGood:
            for result in self._sendError(AlertDescription.decryption_failed,
                    "Encrypted data does not have valid padding"):
                yield result

        # Remove padding
        b = b[:-totalPaddingLength]

        yield b

    def _decryptRecordWithMtE(self, recordType, b):
        #Decrypt if it's a block cipher
        if self._readState.encContext.isBlockCipher:
            blockLength = self._readState.encContext.block_size
            if len(b) % blockLength != 0:
                for result in self._sendError(\
                        AlertDescription.decryption_failed,
                        "Encrypted data not a multiple of blocksize"):
                    yield result
            b = self._readState.encContext.decrypt(b)
            if self.version >= (3,2): #For TLS 1.1, remove explicit IV
                b = b[self._readState.encContext.block_size : ]

            #Check padding
            paddingGood = True
            paddingLength = b[-1]
            if (paddingLength+1) > len(b):
                paddingGood=False
                totalPaddingLength = 0
            else:
                if self.version == (3,0):
                    totalPaddingLength = paddingLength+1
                elif self.version in ((3,1), (3,2), (3,3)):
                    totalPaddingLength = paddingLength+1
                    paddingBytes = b[-totalPaddingLength:-1]
                    for byte in paddingBytes:
                        if byte != paddingLength:
                            paddingGood = False
                            totalPaddingLength = 0
                else:
                    raise AssertionError()

        #Decrypt if it's a stream cipher
        else:
            paddingGood = True
            b = self._readState.encContext.decrypt(b)
            totalPaddingLength = 0

        #Check MAC
        macGood = True
        macLength = self._readState.macContext.digest_size
        endLength = macLength + totalPaddingLength
        if endLength > len(b):
            macGood = False
        else:
            #Read MAC
            startIndex = len(b) - endLength
            endIndex = startIndex + macLength
            checkBytes = b[startIndex : endIndex]

            #Calculate MAC
            seqnumBytes = self._readState.getSeqNumBytes()
            b = b[:-endLength]
            mac = self._readState.macContext.copy()
            mac.update(compatHMAC(seqnumBytes))
            mac.update(compatHMAC(bytearray([recordType])))
            if self.version == (3,0):
                mac.update( compatHMAC(bytearray( [len(b)//256] ) ))
                mac.update( compatHMAC(bytearray( [len(b)%256] ) ))
            elif self.version in ((3,1), (3,2), (3,3)):
                mac.update(compatHMAC(bytearray( [self.version[0]] ) ))
                mac.update(compatHMAC(bytearray( [self.version[1]] ) ))
                mac.update(compatHMAC(bytearray( [len(b)//256] ) ))
                mac.update(compatHMAC(bytearray( [len(b)%256] ) ))
            else:
                raise AssertionError()
            mac.update(compatHMAC(b))
            macBytes = bytearray(mac.digest())

            #Compare MACs
            if macBytes != checkBytes:
                macGood = False

        if not (paddingGood and macGood):
            for result in self._sendError(AlertDescription.bad_record_mac,
                                      "MAC failure (or padding failure)"):
                yield result

        yield b

    def calcPendingStates(self, cipherSuite, masterSecret,
            clientRandom, serverRandom, implementations):
        """
        Calculate and prepare pending cipher status for upcomming
        change_cipher_spec message
        """
        if cipherSuite in CipherSuite.aes128Suites:
            keyLength = 16
            ivLength = 16
            createCipherFunc = createAES
        elif cipherSuite in CipherSuite.aes256Suites:
            keyLength = 32
            ivLength = 16
            createCipherFunc = createAES
        elif cipherSuite in CipherSuite.rc4Suites:
            keyLength = 16
            ivLength = 0
            createCipherFunc = createRC4
        elif cipherSuite in CipherSuite.tripleDESSuites:
            keyLength = 24
            ivLength = 8
            createCipherFunc = createTripleDES
        else:
            raise AssertionError()

        if cipherSuite in CipherSuite.shaSuites:
            macLength = 20
            digestmod = hashlib.sha1
        elif cipherSuite in CipherSuite.sha256Suites:
            macLength = 32
            digestmod = hashlib.sha256
        elif cipherSuite in CipherSuite.md5Suites:
            macLength = 16
            digestmod = hashlib.md5

        if self.version == (3,0):
            createMACFunc = createMAC_SSL
        elif self.version in ((3,1), (3,2), (3,3)):
            createMACFunc = createHMAC

        outputLength = (macLength*2) + (keyLength*2) + (ivLength*2)

        #Calculate Keying Material from Master Secret
        if self.version == (3,0):
            keyBlock = PRF_SSL(masterSecret,
                               serverRandom + clientRandom,
                               outputLength)
        elif self.version in ((3,1), (3,2)):
            keyBlock = PRF(masterSecret,
                           b"key expansion",
                           serverRandom + clientRandom,
                           outputLength)
        elif self.version == (3,3):
            keyBlock = PRF_1_2(masterSecret,
                           b"key expansion",
                           serverRandom + clientRandom,
                           outputLength)
        else:
            raise AssertionError()

        #Slice up Keying Material
        clientPendingState = _ConnectionState()
        serverPendingState = _ConnectionState()
        p = Parser(keyBlock)
        clientMACBlock = p.getFixBytes(macLength)
        serverMACBlock = p.getFixBytes(macLength)
        clientKeyBlock = p.getFixBytes(keyLength)
        serverKeyBlock = p.getFixBytes(keyLength)
        clientIVBlock  = p.getFixBytes(ivLength)
        serverIVBlock  = p.getFixBytes(ivLength)
        clientPendingState.macContext = createMACFunc(
            compatHMAC(clientMACBlock), digestmod=digestmod)
        serverPendingState.macContext = createMACFunc(
            compatHMAC(serverMACBlock), digestmod=digestmod)
        clientPendingState.encContext = createCipherFunc(clientKeyBlock,
                                                         clientIVBlock,
                                                         implementations)
        serverPendingState.encContext = createCipherFunc(serverKeyBlock,
                                                         serverIVBlock,
                                                         implementations)

        #Assign new connection states to pending states
        if self.client:
            self._pendingWriteState = clientPendingState
            self._pendingReadState = serverPendingState
        else:
            self._pendingWriteState = serverPendingState
            self._pendingReadState = clientPendingState

        if self.version >= (3,2) and ivLength:
            #Choose fixedIVBlock for TLS 1.1 (this is encrypted with the CBC
            #residue to create the IV for each sent block)
            self.fixedIVBlock = getRandomBytes(ivLength)

    def changeWriteState(self):
        """
        Change the current cipher status to the pending cipher status for
        write operations.

        This should be used after a call to L{calcPendingStates} was
        performed and directly after sending a L{ChangeCipherSpec} message.
        """
        self._writeState = self._pendingWriteState
        self._pendingWriteState = _ConnectionState()

    def changeReadState(self):
        """
        Change the current cipher status to the pending cipher status for
        read operations.

        This should be used only after a call to L{calcPendingStates} was
        performed and directly after receiving a L{ChangeCipherSpec} message.
        """
        self._readState = self._pendingReadState
        self._pendingReadState = _ConnectionState()
