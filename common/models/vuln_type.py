from enum import Enum


class VulnType(Enum):
    trust_manager = 'TrustManager'
    hostname_verifier = 'HostnameVerifier'
    web_view_client = 'WebViewClient'
    selected_activities = 'Selected Activities'
    https = 'HTTPS URLs Heuristic'
    http = 'HTTP URLs Heuristic'
    https_http = 'HTTP and HTTPS URLs Heuristic'

    def __json__(self):
        return {'value': self.value}
