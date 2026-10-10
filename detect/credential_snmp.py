"""Strict bounded SNMPv1 GET codec. No I/O and no secret-bearing diagnostics."""
import secrets

SYS_DESCR = bytes.fromhex('2b06010201010100')  # 1.3.6.1.2.1.1.1.0 (sysDescr.0)


class InvalidResponse(ValueError):
    pass


def tlv(tag: int, value: bytes) -> bytes:
    size = len(value)
    if size > 4096:
        raise InvalidResponse('BER size limit')
    length = bytes([size]) if size < 128 else bytes([0x82]) + size.to_bytes(2, 'big')
    return bytes([tag]) + length + value


def integer(value: int) -> bytes:
    data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
    if data[0] & 0x80:
        data = b'\x00' + data
    return tlv(2, data)


def build_get(community: str, request_id: int) -> bytes:
    if not 1 <= len(community) <= 64 or any(not 32 <= ord(c) <= 126 for c in community):
        raise ValueError('Unsupported community encoding or size')
    variables = tlv(0x30, tlv(0x30, tlv(6, SYS_DESCR) + tlv(5, b'')))
    pdu = tlv(0xA0, integer(request_id) + integer(0) + integer(0) + variables)
    return tlv(0x30, integer(0) + tlv(4, community.encode('ascii', errors='strict')) + pdu)


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.position = data, 0

    def get(self, expected: int) -> bytes:
        if self.position + 2 > len(self.data):
            raise InvalidResponse('Truncated BER')
        tag, length = self.data[self.position:self.position + 2]
        self.position += 2
        if tag != expected:
            raise InvalidResponse('Unexpected BER type')
        if length & 0x80:
            count = length & 0x7f
            if count not in (1, 2) or self.position + count > len(self.data):
                raise InvalidResponse('Invalid BER length')
            length = int.from_bytes(self.data[self.position:self.position + count], 'big')
            self.position += count
        if length > 4096 or self.position + length > len(self.data):
            raise InvalidResponse('Invalid BER size')
        value = self.data[self.position:self.position + length]
        self.position += length
        return value

    def number(self) -> int:
        raw = self.get(2)
        if not 1 <= len(raw) <= 4 or raw[0] & 0x80 or (len(raw) > 1 and raw[0] == 0 and raw[1] < 128):
            raise InvalidResponse('Invalid BER integer')
        return int.from_bytes(raw, 'big')

    def end(self) -> None:
        if self.position != len(self.data):
            raise InvalidResponse('Trailing BER data')


def classify_response(data: bytes, community: str, request_id: int) -> str:
    """Return READ_OK, OID_UNAVAILABLE, INDICATIVE, or raise InvalidResponse.

    Both positive states are protocol evidence only, never cryptographic proof.
    """
    if len(data) > 4096:
        raise InvalidResponse('Response too large')
    outer = Reader(data)
    message = Reader(outer.get(0x30))
    outer.end()
    if message.number() != 0 or message.get(4) != community.encode('ascii', errors='strict'):
        raise InvalidResponse('Uncorrelated message')
    pdu = Reader(message.get(0xA2))
    message.end()
    if pdu.number() != request_id:
        raise InvalidResponse('Uncorrelated request')
    error, index = pdu.number(), pdu.number()
    variables = Reader(pdu.get(0x30))
    pdu.end()
    # RFC 1157 error responses retain the original variable bindings.
    variable = Reader(variables.get(0x30))
    variables.end()
    if variable.get(6) != SYS_DESCR:
        raise InvalidResponse('Uncorrelated OID')
    if error == 0:
        if index != 0:
            raise InvalidResponse('Invalid error index')
        variable.get(4)  # sysDescr is an OCTET STRING; do not expose its value.
        result = 'READ_OK'
    else:
        if variable.get(5) != b'':
            raise InvalidResponse('Invalid error binding')
        if error == 2 and index == 1:
            result = 'OID_UNAVAILABLE'
        elif (error == 1 and index == 0) or (error == 5 and index == 1):
            result = 'INDICATIVE'
        elif error in (3, 4) and index == 1:
            result = 'INDICATIVE'
        else:
            raise InvalidResponse('Unexpected SNMP error')
    variable.end()
    return result


def new_request_id() -> int:
    return secrets.randbelow(2**31 - 1) + 1
