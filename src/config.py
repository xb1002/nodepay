ipCheck_url = "http://ipinfo.io/json"
DOMAIN_API_ENDPOINTS = {
    "SESSION": "http://api.nodepay.ai/api/auth/session",
    "PING": [
        "http://13.215.134.222/api/network/ping",
        "http://18.139.20.49/api/network/ping",
        "http://3.1.154.253/api/network/ping"
    ]
}
BASE_PING_INTERVAL = 120
MAX_RETRIES = 20

proxy_retry = {}

ACCOUNTS_CONFIG = {}

PROXY_NUM_OF_ACCOUNT = 3

TIMEOUT = 20