import collections
import base64
import json
import time

import OpenSSL.crypto
import six
import requests

from google_oauth.exceptions import AuthenticationError


AUDIENCE = 'https://www.googleapis.com/oauth2/v4/token'
GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
PKCS12_PASSPHRASE = b'notasecret'


def _b64_json(obj):
    json_string = json.dumps(obj, separators=(',', ':')).encode('utf-8')
    return base64.b64encode(json_string)


class ServiceAccount(object):
    """Performs OAuth2 dance for Google API service accounts.

    Retrieves OAuth2 tokens described in Google OAuth2 API
    Server to Server applications.
    https://developers.google.com/identity/protocols/OAuth2ServiceAccount

    Although __init__ method allows for constructing this class,
    it's quite unhandy. Because Google provides two ways of obtaining
    private keys, there are two classmethods (alternate constructors).

    - ServiceAccount.from_json(key, scopes, subject=None)
    - ServiceAccount.from_pkcs12(key, email, scopes, subject=None)

    Google recommends using JSON key file format (which itself holds
    key in PKCS#8 format) - because it includes all other useful
    information about service account. It is possible to use .p12
    files with latter method, but you have to supply it with email
    as well.
    """

    def __init__(self, key, email, scopes, subject=None):
        """Constructs new instance for given service account.

        Although it is possible to use this, it isn't recommended.
        You have to parse private key yourself and make
        ``OpenSSL.crypto.PKey`` out of it. Because Google Developer Console
        generates keys in two file formats - JSON and PKCS#12, it is
        advised to use ``ServiceAccount.from_json`` or
        ``ServiceAccount.from_pkcs12``.

        Args:
            key (OpenSSL.crypto.PKey) - RSA private key used for signing JWT.
            email (str) - Service account email.
            scopes (Union[str, collections.Iterable[str]]) -
                List of permissions that the application requests.
            subject (str) - The email address of the user for which
                the application is requesting delegated access.
        """
        self._key = None
        self._email = None
        self._scopes = None
        self._subject = None
        self._issued_at = None
        self._access_token = None

        self.key = key
        self.email = email
        self.scopes = scopes
        self.subject = subject

    @classmethod
    def from_json(cls, key, scopes, subject=None):
        """Alternate constructor intended for using JSON format of private key.

        Args:
            key (dict) - Parsed JSON with service account credentials.
            scopes (Union[str, collections.Iterable[str]]) -
                List of permissions that the application requests.
            subject (str) - The email address of the user for which
                the application is requesting delegated access.

        Returns:
            ServiceAccount
        """
        credentials_type = key['type']
        if credentials_type != 'service_account':
            raise ValueError('key: expected type service_account '
                             '(got %s)' % credentials_type)
        email = key['client_email']
        key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                             key['private_key'])

        return cls(key=key, email=email, scopes=scopes, subject=subject)

    @classmethod
    def from_pkcs12(cls, key, email, scopes, subject=None,
                    passphrase=PKCS12_PASSPHRASE):
        """Alternate constructor intended for using .p12 files.

        Args:
            key (dict) - Parsed JSON with service account credentials.
            email (str) - Service account email.
            scopes (Union[str, collections.Iterable[str]]) -
                List of permissions that the application requests.
            subject (str) - The email address of the user for which
                the application is requesting delegated access.
            passphrase (str) - Passphrase of private key file.
                Google generates .p12 files secured with fixed 'notasecret'
                passphrase, so if you didn't change it it's fine to omit
                this parameter.

        Returns:
            ServiceAccount
        """
        key = OpenSSL.crypto.load_pkcs12(key, passphrase).get_privatekey()
        return cls(key=key, email=email, scopes=scopes, subject=subject)

    @property
    def key(self):
        """RSA private key used to sign JSON Web Tokens.

        Returns:
            OpenSSL.crypto.PKey
        """
        return self._key

    @key.setter
    def key(self, key):
        if not isinstance(key, OpenSSL.crypto.PKey):
            raise TypeError('key: expected OpenSSL.crypto.PKey instance '
                            '(got %s)' % type(key))
        self._key = key

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, email):
        if not email:
            raise ValueError('email: expected service account email,'
                             '(got %s)' % email)
        self._email = email

    @property
    def scopes(self):
        """Scopes requested in OAuth2 access token request.

        Although Google accepts scopes as space delimited string,
        accessing this property will return tuple of scopes.

        Returns:
            tuple[str]
        """
        return self._scopes.split()

    @scopes.setter
    def scopes(self, scopes):
        if isinstance(scopes, six.string_types):
            self._scopes = scopes
        elif isinstance(scopes, collections.Iterable):
            self._scopes = ' '.join(scopes)
        else:
            raise ValueError('scopes: expected string or iterable of strings')

    @property
    def subject(self):
        return self._subject

    @subject.setter
    def subject(self, subject):
        if subject is not None and not subject:
            raise ValueError('subject: expected None or non-empty string,'
                             '(got %s)' % subject)
        self._subject = subject

    @property
    def issued_at(self):
        """Time when access token was requested, as seconds since epoch.

        Note:
            Accessing this property when there wasn't any request attempts
            will return current time.

        Returns:
            int
        """
        issued_at = self._issued_at
        if issued_at is None:
            self._issued_at = int(time.time())
        return self._issued_at

    @issued_at.deleter
    def issued_at(self):
        self._issued_at = None

    @property
    def expiration_time(self):
        """Expiration time of access token, as seconds since epoch.

        Although it is possible to request access tokens with any
        expiration time less than one hour, Google regardless of
        value sent will issue the token for one hour.

        Returns:
            int
        """
        return self.issued_at + 3600

    @property
    def access_token(self):
        """Stores always valid OAuth2 access token.

        Note:
            Accessing this property may result in HTTP request.

        Returns:
            str
        """
        if (self._access_token is None or
                self.expiration_time <= int(time.time())):
            resp = self.make_access_request()
            self._access_token = resp.json()['access_token']

        return self._access_token

    @staticmethod
    def header():
        header = {
            'alg': 'RS256',
            'typ': 'JWT',
        }
        return _b64_json(header)

    def claims(self):
        claims = {
            'iss': self.email,
            'scope': self._scopes,
            'aud': AUDIENCE,
            'iat': self.issued_at,
            'exp': self.expiration_time,
        }

        if self.subject is not None:
            claims['sub'] = self.subject

        return _b64_json(claims)

    def signature(self):
        message = b'.'.join((self.header(), self.claims()))
        signature = OpenSSL.crypto.sign(self.key, message, 'sha256')
        signature_b64encoded = base64.b64encode(signature)

        return signature_b64encoded

    def make_access_request(self):
        """Makes an OAuth2 access token request with crafted JWT and signature.

        The core of this module. Based on arguments it creates proper JWT
        for you and signs it with supplied private key.
        Regardless of present valid token, it always clears
        ``issued_at`` property, which in turn results in requesting
        fresh OAuth2 access token.

        Returns:
            requests.Response

        Raises:
            google_oauth.exceptions.AuthenticationError:
                If there was any non-200 HTTP-code from Google.
            requests.RequestException:
                Something went wrong when doing HTTP request.
        """
        del self.issued_at

        assertion = b'.'.join((self.header(), self.claims(), self.signature()))
        post_data = {
            'grant_type': GRANT_TYPE,
            'assertion': assertion,
        }

        resp = requests.post(AUDIENCE, post_data)

        if resp.status_code != 200:
            raise AuthenticationError(resp)

        return resp

    def authorized_request(self, method, url, **kwargs):
        """Shortcut for requests.request with proper Authorization header.

        Note:
            If you put auth keyword argument or Authorization in headers
            keyword argument, this will raise an exception.
            Decide what you want to do!

        Args:
            method (str) - HTTP method of this request, like GET or POST.
            url (str) - URL of this request (one of Google APIs).

        Examples:
            >>> scope = 'https://www.googleapis.com/auth/plus.login'
            >>> url = 'https://www.googleapis.com/plus/v1/people' \
            >>>         '?query=Guuido+van+Rossum'
            >>> key = json.load(open('/path/to/credentials.json'))
            >>> auth = ServiceAccount.from_json(key=key, scopes=scope)
            >>> auth.authorized_request(method='get', url=url)

        Returns:
            requests.Response
        """
        headers = kwargs.pop('headers', {})
        if headers.get('Authorization') or kwargs.get('auth'):
            raise ValueError("Found custom Authorization header, "
                             "method call would override it.")
        headers['Authorization'] = 'Bearer ' + self.access_token

        return requests.request(method, url, headers=headers, **kwargs)
