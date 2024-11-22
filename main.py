import aiohttp
import random
import fake_useragent
import requests
import uuid
import queue
from loguru import logger
import time
import asyncio
from src.config import *

left_proxies = []

def get_user_agent() -> str: # 获取随机的user_agent
    user_agent = fake_useragent.UserAgent()
    return user_agent.random

def get_np_tokens() -> list: # 获取np_token.txt中的全部np_token
    np_token_file = 'np_token.txt'
    try:
        with open(np_token_file) as f:
            np_tokens = f.read().split('\n')
    except FileNotFoundError:
        raise FileNotFoundError(f"{np_token_file} file not found")
    np_tokens = [token for token in np_tokens if token]
    if not np_tokens:
        raise ValueError("No np tokens found")
    return np_tokens

def _transform_proxy(proxy) -> str: # 这是aiohttp的代理格式
    l = proxy.split(':')
    res = None
    if len(l) == 4:
        res = f'http://{l[2]}:{l[3]}@{l[0]}:{l[1]}'
    if len(l) == 2:
        res = f'http://{l[0]}:{l[1]}'
    if res is None:
        raise ValueError(f"Invalid proxy: {proxy}")
    return res

def get_proxies() -> list: # 获取proxy.txt中的全部代理
    try:
        proxy_file = 'proxys.txt'
        raw_proxies = open(proxy_file).read().split('\n')
    except FileNotFoundError:
        raise FileNotFoundError(f"{proxy_file} file not found")
    raw_proxies = [proxy for proxy in raw_proxies if proxy]
    return [_transform_proxy(proxy) for proxy in raw_proxies]

def get_uuid() -> str: # 生成browser_id
    return str(uuid.uuid4())

def get_header(np_token, user_agent) -> dict: # 生成请求头
    headers = {
        "Authorization": f"Bearer {np_token}",
        "Content-Type": "application/json",
        "User-Agent": user_agent,
        "Accept": "application/json",
    }
    return headers

def get_ping_data(uid, browser_id, timestamp, version="2.2.7") -> dict: # 生成ping请求的数据
    data = {
        "id":uid,
        "browser_id":browser_id,
        "timestamp":timestamp,
        "version":version,
    }
    return data

def _get_ip_address(proxy) -> str: # 获取ip具体地址
    try:
        res = requests.get(ipCheck_url, proxies={"http":proxy, "https":proxy}, timeout=5)
        res.raise_for_status()
        ip = res.json()['ip']
        logger.info(f"IP Address: {ip}")
        return ip
    except Exception as e:
        logger.error(f"Error in get_ip_address: {e} by {proxy}")

def get_ping_url() -> str: # 随机选择ping_url
    return random.choice(DOMAIN_API_ENDPOINTS["PING"])

def get_ping_interval() -> int: # 获取ping间隔
    return random.randint(0,20) + BASE_PING_INTERVAL

def set_account_config(np_token, ping_url, proxys:list) -> None: # 配置每一个账号
    global ACCOUNTS_CONFIG
    data = {
        "uid":"",
        "ping_url":ping_url,
        # 考虑具体的ip地址
        # "connect_config":[{"proxy":proxy, "ip":_get_ip_address(proxy),
        #                     "user_agent":get_user_agent()} for proxy in proxys],

        # 不考虑具体的ip地址
        "connect_config":[{"proxy":proxy,"user_agent":get_user_agent()} for proxy in proxys],
    }
    ACCOUNTS_CONFIG[np_token] = data
    
def session_valid_resp(resp_json) -> str: # 如果session创建成功，返回账户uid
    if resp_json['code'] == 0:
        return resp_json['data']['uid']
    else:
        raise ValueError(f"{resp_json}")
    
def ping_valid_resp(resp_json) -> None: # 如果ping成功，返回None, 否则抛出异常
    if resp_json['code'] == 0:
        return resp_json['data']['ip_score']
    else:
        raise ValueError(f"{resp_json}")
    
async def _create_session(session_url, np_token, user_agent, proxy) -> None: # 创建session
    global proxy_retry
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
            headers = get_header(np_token, user_agent)
            async with session.post(session_url, headers=headers, proxy=proxy, data={}, timeout=TIMEOUT) as res:
                res.raise_for_status()
                res_json = await res.json()
                uid = session_valid_resp(res_json)
                ACCOUNTS_CONFIG[np_token]['uid'] = uid
                logger.info(f"Session created for {uid} with proxy {proxy}")
                proxy_retry[proxy] = 0
                return True
    except Exception as e:
        logger.error(f"Error in create_session: {e} by {np_token[:30]} with proxy {proxy}")
        proxy_retry[proxy] = proxy_retry.get(proxy, 0) + 1
        await asyncio.sleep(random.randint(0, 10)+30)
        return False

async def _ping(ping_url, np_token, user_agent, proxy) -> None: # ping
    global proxy_retry
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
            headers = get_header(np_token, user_agent)
            data = get_ping_data(ACCOUNTS_CONFIG[np_token]['uid'], get_uuid(), int(time.time()))
            async with session.post(ping_url, headers=headers, proxy=proxy, json=data, timeout=TIMEOUT) as res:
                res.raise_for_status()
                res_json = await res.json()
                ip_score = ping_valid_resp(res_json)
                logger.info(f"Ping success for {ACCOUNTS_CONFIG[np_token]['uid']} with proxy {proxy}, ip_score: {ip_score}")
                proxy_retry[proxy] = 0
                return True
    except Exception as e:
        logger.error(f"Error in ping: {e} by {ACCOUNTS_CONFIG[np_token]['uid']} with proxy {proxy}")
        proxy_retry[proxy] = proxy_retry.get(proxy, 0) + 1
        return False

async def app(np_token, ping_url, user_agent, proxy) -> None:
    proxy_retry[proxy] = 0
    while True and proxy_retry[proxy] < MAX_RETRIES:
        if (await _create_session(DOMAIN_API_ENDPOINTS["SESSION"], np_token, user_agent, proxy)):
        # if True:
            await asyncio.sleep(10)
            await _ping(ping_url, np_token, user_agent, proxy)
            while True and proxy_retry[proxy] < MAX_RETRIES:
                await asyncio.sleep(get_ping_interval())
                await _ping(ping_url, np_token, user_agent, proxy)
    global left_proxies
    if len(left_proxies) > 0:
        await app(np_token, ping_url, user_agent, left_proxies.pop())

def assign_proxies_to_single_account(proxies, np_tokens) -> dict[str, list]: # 每个账户分配一批代理
    # PROXY_NUM_OF_ACCOUNT,
    proxies_to_single_account = {np_token:[] for np_token in np_tokens}
    for i in range(PROXY_NUM_OF_ACCOUNT):
        for j in range(len(np_tokens)):
            if len(proxies) == 0:
                return proxies_to_single_account, proxies
            np_token = np_tokens[j]
            proxies_to_single_account[np_token].append(proxies.pop())
    return proxies_to_single_account, proxies
            
async def main():
    global left_proxies
    proxies = get_proxies()
    np_tokens = get_np_tokens()
    proxies_to_single_account,left_proxies = assign_proxies_to_single_account(proxies, np_tokens)
    for np_token,proxies in proxies_to_single_account.items():
        set_account_config(np_token, get_ping_url(), proxies)
    tasks = []
    for np_token, data in ACCOUNTS_CONFIG.items():
        for single_data in data['connect_config']:
            tasks.append(app(np_token, data['ping_url'], single_data['user_agent'], single_data['proxy']))
    await asyncio.gather(*tasks)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Exiting...")