class AuthenticationError(Exception):
    """Generic OAuth2 authentication error.

    Attributes:
        message (dict) - parsed JSON response
        status_code (int) - HTTP code returned
        response (requests.Response) - response from Google

    Args:
        response (requests.Response) - response from Google
    """
    def __init__(self, response):
        self.response = response
        self.message = response.json()
        self.status_code = response.status_code
