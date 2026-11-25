import base64
import hashlib
import hmac
import json
import unittest

from opendrm import playback_token


def decode(part: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


class PlaybackTokenTest(unittest.TestCase):
    secret = "s" * 32

    def test_claims_and_signature(self):
        tok = playback_token(self.secret, user=8812, title="ip-c3", device="pixel8", claims={"plan": "paid"}, ttl=60, now=1_800_000_000)
        header, body, sig = tok.split(".")
        self.assertEqual(decode(header), {"alg": "HS256", "typ": "JWT"})
        self.assertEqual(
            decode(body),
            {"sub": "8812", "title": "ip-c3", "device": "pixel8", "plan": "paid", "iat": 1_800_000_000, "exp": 1_800_000_060},
        )
        expected = hmac.new(self.secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
        self.assertEqual(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)), expected)

    def test_device_optional(self):
        tok = playback_token(self.secret, user="u", title="t", now=0)
        self.assertNotIn("device", decode(tok.split(".")[1]))

    def test_rejects_bad_input(self):
        for kwargs in (
            {"secret": "", "user": "u", "title": "t"},
            {"secret": self.secret, "user": "", "title": "t"},
            {"secret": self.secret, "user": "u", "title": ""},
            {"secret": self.secret, "user": "u", "title": "t", "ttl": 0},
            {"secret": self.secret, "user": "u", "title": "t", "claims": {"sub": "admin"}},
            {"secret": self.secret, "user": "u", "title": "t", "claims": {"exp": 9999999999}},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                playback_token(**kwargs)

    def test_bytes_secret(self):
        a = playback_token(self.secret, user="u", title="t", now=1)
        b = playback_token(self.secret.encode(), user="u", title="t", now=1)
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
