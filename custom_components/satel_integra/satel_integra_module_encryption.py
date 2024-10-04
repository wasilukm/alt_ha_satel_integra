from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import os
import logging

_LOGGER = logging.getLogger(__name__)


class SatelEncryption:

    def __init__(self, integration_key: str):
        self.cipher = AES.new(self.integration_key_to_encryption_key(integration_key), AES.MODE_ECB)

    @classmethod
    def integration_key_to_encryption_key(cls, integration_key: str) -> bytes:
        password_bytes = integration_key.encode()
        key_bytes = bytearray(24)

        for i in range(12):
            key_bytes[i] = key_bytes[i + 12] = password_bytes[i] if i < len(password_bytes) else 0x20
        return bytes(key_bytes)

    def decrypt(self, buffer):
        cv = bytearray(16)
        c = bytearray(16)
        temp = bytearray(16)
        count = len(buffer)
        decrypted = bytearray(count)

        cv = bytearray(self.cipher.encrypt(bytes(cv)))
        index = 0

        while count > 0:
            if count > 15:
                count -= 16
                temp[:] = buffer[index:index + 16]
                c[:] = buffer[index:index + 16]
                c = bytearray(self.cipher.decrypt(bytes(c)))
                for i in range(16):
                    c[i] ^= cv[i]
                    cv[i] = temp[i]
                decrypted[index:index + 16] = c
                index += 16
            else:
                c[:count] = buffer[index:index + count]
                cv = self.cipher.encrypt(bytes(cv))
                for i in range(16):
                    c[i] ^= cv[i]
                decrypted[index:index + count] = c[:count]
                count = 0
        return decrypted

    def encrypt(self, buffer):
        cv = bytearray(16)
        p = bytearray(16)
        count = len(buffer)
        encrypted = bytearray(count)

        cv = bytearray(self.cipher.encrypt(bytes(cv)))
        index = 0

        while count > 0:
            if count > 15:
                count -= 16
                p[:] = buffer[index:index + 16]
                for i in range(16):
                    p[i] ^= cv[i]
                p = bytearray(self.cipher.encrypt(bytes(p)))
                cv[:] = p
                encrypted[index:index + 16] = p
                index += 16
            else:
                p[:count] = buffer[index:index + count]
                cv = self.cipher.encrypt(bytes(cv))
                for i in range(16):
                    p[i] ^= cv[i]
                encrypted[index:index + count] = p[:count]
                count = 0
        return bytes(encrypted)


class EncryptedCommunicationHandler:
    """Handler for Satel encrypted communications.

    :param integration_key:
        Satel integration key to be used for encrypting and decrypting data.

    """

    next_id_s: int = 0

    def __init__(self, integration_key: str):
        self._rolling_counter: int = 0
        # There will be a new value of id_s for each instance . As there will
        # be rather one client this doesn't have much use. However id_s value
        # may show how many reconnections there where.
        self._set_id_s()
        self._id_r: int = 0
        self._satel_encryption = SatelEncryption(integration_key)

    def _set_id_s(self):
        self._id_s: int = EncryptedCommunicationHandler.next_id_s
        EncryptedCommunicationHandler.next_id_s = os.urandom(1)[0]

    def _prepare_header(self) -> bytes:
        self._set_id_s()
        header = (os.urandom(2) +
                  self._rolling_counter.to_bytes(2, 'big') +
                  self._id_s.to_bytes(1, 'big') +
                  self._id_r.to_bytes(1, 'big'))
        self._rolling_counter += 1
        self._rolling_counter &= 0xFFFF

        # int randomValue = this.rand.nextInt();
        # data[0] = (byte) (randomValue >> 8);
        # data[1] = (byte) (randomValue & 0xff);
        # data[2] = (byte) (this.rollingCounter >> 8);
        # data[3] = (byte) (this.rollingCounter & 0xff);
        # data[4] = this.idS = (byte) this.rand.nextInt();
        # data[5] = this.idR;
        # ++this.rollingCounter;

        return header

    def prepare_pdu(self, message: bytes) -> bytes:
        _LOGGER.debug(f'Prepare protocol data unit for {message.hex()=}')
        """.

        :param message: message to be included in PDU

        :returns: encrypted PDU with given message

        """
        pdu = self._prepare_header() + message
        encrypted_pdu = self._satel_encryption.encrypt(pdu)
        return encrypted_pdu

    def extract_data_from_pdu(self, pdu: bytes) -> bytes:
        """Extract data from protocol data unit.

        :param pdu: PDU from which a message to be extracted

        :returns: extracted message

        """
        decrypted_pdu = self._satel_encryption.decrypt(pdu)
        header = decrypted_pdu[:6]
        data = decrypted_pdu[6:]
        self._id_r = header[4]
        if (self._id_s & 0xFF) != decrypted_pdu[5]:
            raise RuntimeError(
                f'Incorrect value of ID_S, received \\x{decrypted_pdu[5]:x} '
                f'but expected \\x{self._id_s:x}\n'
                'Decrypted data: %s' % ''.join(
                    '\\x{:02x}'.format(x) for x in decrypted_pdu))
        return bytes(data)
