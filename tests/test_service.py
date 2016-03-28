import json
import time
import unittest

import OpenSSL.crypto

from google_oauth.service import AuthenticationError, ServiceAccount


SCOPE = 'https://www.googleapis.com/auth/plus.login'
URL = 'https://www.googleapis.com/plus/v1/people?query=Guuido+van+Rossum'


class TestService(unittest.TestCase):
    def setUp(self):
        self.auth = ServiceAccount(key=OpenSSL.crypto.PKey(),
                                   email='my@email.net',
                                   scopes=SCOPE)
        self.auth._issued_at = time.time()
        self.auth._access_token = 'thismustbeavalidtoken!'

    def test_wrong_credentials(self):
        self.auth.key.generate_key(type=OpenSSL.crypto.TYPE_RSA, bits=2048)

        with self.assertRaises(AuthenticationError):
            self.auth.make_access_request()

    def test_auth_kwarg(self):
        with self.assertRaises(ValueError):
            self.auth.authorized_request('get', URL, auth=('login', 'pass'))

    def test_explicit_auth_header(self):
        headers = dict(Authorization='Basic: ihaveb64encodedthis')

        with self.assertRaises(ValueError):
            self.auth.authorized_request('get', URL, headers=headers)

    def test_expired_token(self):
        self.auth.key.generate_key(type=OpenSSL.crypto.TYPE_RSA, bits=2048)
        self.auth._issued_at = time.time() - 3601

        # since we have mocked our credentials it will raise an exception
        with self.assertRaises(AuthenticationError):
            self.auth.access_token


class TestServiceKey(unittest.TestCase):
    def test_json(self):
        with open('key.json') as f:
            key = json.load(f)

        auth = ServiceAccount.from_json(key=key, scopes=SCOPE)
        self.assertIsNotNone(auth.access_token)

        resp = auth.authorized_request('get', URL)
        self.assertEqual(resp.status_code, 200)

    def test_p12(self):
        with open('key.p12', 'rb') as f:
            key = f.read()

        with open('email.txt') as f:
            email = f.read().strip()

        auth = ServiceAccount.from_pkcs12(key=key,
                                          email=email,
                                          scopes=SCOPE)
        self.assertIsNotNone(auth.access_token)

        resp = auth.authorized_request('get', URL)
        self.assertEqual(resp.status_code, 200)
