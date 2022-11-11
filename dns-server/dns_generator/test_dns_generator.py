#!/usr/bin/env python3

import unittest
import unittest.mock as mock
from dns_generator import DNSGen


class TestDnsGen(unittest.TestCase):
    """
    Tests for DNSGen class to ensure valid responses generated and proper handling of invalid requests
    """

    def test_valid_request_valid_response(self):
        dns_request = b'\x1d\xf1\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x03xyz\x03com\x00\x00\x01\x00\x01' \
                      b'\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x00'
        d = DNSGen(dns_request)
        resp = d.make_response()
        ancount = int.from_bytes(resp[6:8], byteorder='big')
        req_byte3 = dns_request[2:3]

        self.assertEqual(dns_request[0:2], resp[0:2])  # ID same
        self.assertNotEqual(req_byte3, resp[2:3])  # 3rd byte not same as qr flips to 1 but opcode stays same or changes
        self.assertEqual(resp[3:4], b"\x00")    # no recursion available, no error code
        self.assertEqual(dns_request[4:6], resp[4:6])   # qdcount same as request
        self.assertGreaterEqual(ancount, 1)  # ancount >= 1
        self.assertEqual(dns_request[12:20], resp[12:20])

        compression_count = 0
        c0 = False
        for byte in resp[25:]:
            if byte == 192:   # byte == "\xc0"
                c0 = True
            if byte == 12 and c0:    # byte == "\x0c" and previous byte was "\xc0"
                c0 = False
                compression_count += 1
        self.assertEqual(compression_count, ancount)    # number of answers = ancount


if __name__ == "__main__":
    unittest.main()
