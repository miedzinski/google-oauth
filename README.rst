Google OAuth Service
********************

.. image:: https://img.shields.io/travis/miedzinski/google-oauth.svg
    :target: https://travis-ci.org/miedzinski/google-oauth/builds
.. image:: https://img.shields.io/codecov/c/github/miedzinski/google-oauth.svg
    :target: https://codecov.io/github/miedzinski/google-oauth

``google-oauth`` aims to implement Google OAuth2.

Installation
============

Requires Python 2.7 or 3.3+.

Use ``pip``:

    $ pip install google-oauth

Or download code rom GitHub and install it manually with ``setuptools``:

    $ git clone https://github.com/miedzinski/google-oauth2-service.git
    $ cd google-oauth
    $ python setup.py install

In case of ``pyOpenSSL`` build failing, install openssl headers.
On Debian based distributions:

    $ apt-get install libssl-dev

Usage
=====

At this moment, there is only `Server to Server` flow implemented.

OAuth2 for service accounts
---------------------------

First, create ``ServiceAccount`` object. The best way to achieve this
is using one of two classmethods:

    - ServiceAccount.from_json
    - ServiceAccount.from_pkcs12

Google recommends JSON key format, so we will use it.
Both methods are documented in source code.

    >>> key = json.load(open('/path/to/credentials.json'))
    >>> auth = ServiceAccount.from_json(key=key, scopes=scope)
    >>> auth.access_token

And that's it - OAuth2 access token is available as ``access_token`` property.
If you think token's lifetime will be longer than object's, you can cache it
in file or database of your choice.
Otherwise, you can use a ``GoogleService.authorized_request``, which is
a handy shortcut to ``requests.request`` with proper ``Authorization`` header.
Subsequent calls to this method won't request new access tokens unless
previous one expired.

Let's search for Guuido van Rossum on Google+

    >>> scope = 'https://www.googleapis.com/auth/plus.login'
    >>> url = 'https://www.googleapis.com/plus/v1/people' \
    >>>         '?query=Guuido+van+Rossum'
    >>> resp = auth.authorized_request(method='get', url=url)

``resp`` is now an instance of ``requests.Response``, from which we can
extract all the data we need.

Documentation
=============

Source code is fully documented with docstrings.

TODO
====

- Implement three-legged OAuth2 (for web server applications).

Contributing
============

All contributors are welcome! Make sure the tests pass and don't forget
to write your own tests if you code new stuff.
If you want to submit a patch, use GitHub pull requests.
