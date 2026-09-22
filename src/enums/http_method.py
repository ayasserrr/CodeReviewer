from enum import StrEnum


class HttpMethod(StrEnum):
    """HTTP methods recognized by the endpoint detector."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"
