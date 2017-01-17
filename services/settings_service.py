from models.default_settings import default_certificates


def get_vulnerability_types():
    return ['TrustManager', 'HostnameVerifier', "WebViewClient"]


def get_certificates():
    return default_certificates