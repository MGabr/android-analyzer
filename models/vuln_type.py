from enum import Enum


class VulnType(Enum):
    trust_manager = 'TrustManager'
    hostname_verifier = 'HostnameVerifier'
    web_view_client = 'WebViewClient'
