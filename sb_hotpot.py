import hashlib
import json
import random
import time
import http.client
import urllib.parse
import rsa
import base64
import socks


def encrypt_with_rsa(plaintext):
    public_key_str = """
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDcwjySP4T61/8neKRDzjXw7qU1Q1Pt7MrOSz5uu1GmIGT0sbxsc1ZY0YX7LBvSlB9EdOjVkVfvgNM/ssmBKQw/cVRhK5YzEdUGQwvvvbYl97diYfTfr52DVoeRdKlodSnuKmSBpO4jOOoEewRqPBly9HUHclmQJo0TUig9DzPbwIDAQAB
    """
    formatted_public_key = "-----BEGIN PUBLIC KEY-----\n" + public_key_str + "\n-----END PUBLIC KEY-----"
    public_key = rsa.PublicKey.load_pkcs1_openssl_pem(formatted_public_key.encode())
    ciphertext = rsa.encrypt(plaintext.encode(), public_key)
    hex_ciphertext = ciphertext.hex()
    return hex_ciphertext


def enc_json(sid, uid):
    entrypTime = encrypt_with_rsa('30')
    entrypTime = base64.b64encode(bytes.fromhex(entrypTime)).decode()
    json = '{"entrypTime":"' + entrypTime + '","sid":"' + sid + '","time":"30","uid":"' + uid + '"}'
    # print(json)
    enc_text = ""
    substring_length = 117
    substrings = split_text(json, substring_length)
    for substring in substrings:
        # print(substring)
        encText = encrypt_with_rsa(substring)
        # print(encText)
        enc_text = enc_text + encText
    return base64.b64encode(bytes.fromhex(enc_text)).decode()


def split_text(text, length):
    return [text[i:i + length] for i in range(0, len(text), length)]


def get_request(username, sid, uid, token, proxy):
    proxy_address = proxy

    # Extract proxy details
    proxy_parts = proxy_address.split('@')
    proxy_credentials = proxy_parts[0].split(':')
    proxy_host_port = proxy_parts[1].split(':')

    proxy_username = proxy_credentials[0]
    proxy_password = proxy_credentials[1]
    proxy_host = proxy_host_port[0]
    proxy_port = int(proxy_host_port[1])
    socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port, username=proxy_username, password=proxy_password)
    http.client.HTTPConnection = socks.socksocket
    entrypString = enc_json(sid, uid)
    body = {
        "entrypString": entrypString,
        "userToken": token
    }
    payload = urllib.parse.urlencode(body)
    headers = {
        "Host": "music.hotpot.io",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Authorization": "Bearer " + token,
        "Content-Length": len(payload),
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    }
    try:
        url = "music.hotpot.io"
        path = "/music/play/listenTime"
        conn = http.client.HTTPSConnection(url)
        conn.request("POST", path, payload, headers)
        response = conn.getresponse()
        if response.status == 200:
            ciphertext = response.read().decode("utf-8")
            print(username + ":    " + ciphertext)
    except:
        pass


def hotpot_login(username, password):
    credentials = {"username": username, "password": password}
    encoded_credentials = json.dumps(credentials)
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Content-Length": len(encoded_credentials),
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Origin": "https://www.hotpot.io",
        "Referer": "https://www.hotpot.io/"

    }
    conn = http.client.HTTPSConnection("gw.hotpot.io")
    conn.request("POST", "/eut-interface/login", encoded_credentials, headers)
    response = conn.getresponse()
    res_json = response.read().decode()
    res_json = json.loads(res_json)
    conn.close()
    accessToken = res_json['data']['accessToken']
    uid = res_json['data']['userId']
    return accessToken, uid

def hotpot_claim(token,proxy):
    proxy_address = proxy
    proxy_parts = proxy_address.split('@')
    proxy_credentials = proxy_parts[0].split(':')
    proxy_host_port = proxy_parts[1].split(':')
    proxy_username = proxy_credentials[0]
    proxy_password = proxy_credentials[1]
    proxy_host = proxy_host_port[0]
    proxy_port = int(proxy_host_port[1])
    socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port, username=proxy_username, password=proxy_password)
    http.client.HTTPConnection = socks.socksocket
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Content-Length": "2",
        "Content-Type": "application/json",
        "Authorization": token,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Origin": "https://www.hotpot.io",
        "Referer": "https://www.hotpot.io/"

    }
    conn = http.client.HTTPSConnection("gw.hotpot.io")
    data = "{}"
    conn.request("POST", "/eut-interface/profit_v2/claim_profit", data, headers)
    response = conn.getresponse()
    print("Click Claim", response.status)
    res_json = response.read().decode()
    res_json = json.loads(res_json)
    print(res_json)
    conn.close()

def encrypt_with_md5(text):
    string_to_hash = "bce202207?!bce" + text + "bce2020?!#@"
    encoded_string = string_to_hash.encode('utf-8')
    md5_hash = hashlib.md5()
    md5_hash.update(encoded_string)
    encrypted_text = md5_hash.hexdigest()
    return encrypted_text


if __name__ == "__main__":
    hotpot_list = [
        "username----password----proxy"
#proxy example: username:password@proxy_host:port
      
    ]
    video_list = [
        "1780848852227903490",
        "1780622685730295810",
        "1780486878604349441",
        "1780467534830817281",
        "1780042866087231490",
        "1779766437915197441",
        "1779487428161634305",
        "1779482061658718209",
        "1779468818370330625",
        "1779449865946333186",
        "1779468348729917442"
    ]
    accessArray = []
    for hotpot in hotpot_list:
        username, password, sock5_proxy = hotpot.split("----")
        password = encrypt_with_md5(password)
        print("login_success:  "+username, password, sock5_proxy)
        accessToken, uid = hotpot_login(username, password)
        sid = random.choice(video_list)
        accessStr = username + "----" + sid + "----" + uid + "----" + accessToken + "----" + sock5_proxy
        accessArray.append(accessStr)
        hotpot_claim(accessToken, sock5_proxy)
    while(1):
        for i in range(0, len(accessArray)):
            username, sid, uid, accessToken, sock5_proxy = str(accessArray[i]).split("----")
            get_request(username, sid, uid, accessToken, sock5_proxy)
        time.sleep(30)
