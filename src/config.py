ipCheck_url = "http://ipinfo.io/json"
DOMAIN_API_ENDPOINTS = {
    "SESSION": "http://api.nodepay.ai/api/auth/session",
    "PING": [
        "http://13.215.134.222/api/network/ping",
        "http://18.139.20.49/api/network/ping",
        "http://52.74.35.173/api/network/ping",
        "http://52.77.10.116/api/network/ping",
        "http://3.1.154.253/api/network/ping"
    ]
}
BASE_PING_INTERVAL = 100
MAX_RETRIES = 20
retry = 0

ACCOUNTS_CONFIG = {}