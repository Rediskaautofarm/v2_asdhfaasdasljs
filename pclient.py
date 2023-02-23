import json
import os
import random
import time
from base64 import b64encode
from binascii import hexlify
from hashlib import sha1
from hmac import new
from multiprocessing import Process
from uuid import UUID

import requests
import urllib3.exceptions
from json_minify import json_minify

PREFIX = bytes.fromhex("19")
SIG_KEY = bytes.fromhex("DFA5ED192DDA6E88A12FE12130DC6206B1251E44")
DEVICE_KEY = bytes.fromhex("E7309ECC0953C6FA60005B2765F99DBBC965C8E9")


class Headers:
    def __init__(self, data=None, content_type=None, deviceId: str = None, sid: str = None):
        self.sid = sid
        if deviceId is not None:
            self.deviceId = deviceId
        else:
            self.deviceId = Generate().deviceId()
        self.headers = {
            "NDCDEVICEID": self.deviceId,
            "Accept-Language": "en-US",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-G965N "
                          "Build/star2ltexx-user 7.1.; com.narvii.amino.master/3.4.33602)",
            "Host": "service.narvii.com",
            "Accept-Encoding": "gzip",
            "Connection": "Upgrade"
        }
        self.postheaders = {
            "Accept-Language": "en-US",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "Apple iPhone12,1 iOS v15.5 Main/3.12.2",
            "Host": "service.narvii.com",
            "Accept-Encoding": "gzip",
            "Connection": "Upgrade"
        }

        if data is not None:
            self.headers["Content-Length"] = str(len(data))
            self.headers["NDC-MSG-SIG"] = Generate().signature(data=data)
        if self.sid is not None:
            self.headers["NDCAUTH"] = f"sid={self.sid}"
        if content_type is not None:
            self.headers["Content-Type"] = content_type

        if deviceId: self.postheaders["NDCDEVICEID"] = deviceId
        if data:
            self.postheaders["Content-Length"] = str(len(data))
            self.postheaders["NDC-MSG-SIG"] = Generate().signature(data=data)
        if sid: self.postheaders["NDCAUTH"] = f"sid={sid}"
        if content_type: self.postheaders["Content-Type"] = content_type

        self.reg_headers = {
            'Accept-Language': 'en-US',
            'Content-Type': 'application/json; charset=utf-8',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1; LG-UK495 '
                          'Build/MRA58K; com.narvii.amino.master/3.3.33180)',
            'Host': 'service.narvii.com',
            'Accept-Encoding': 'gzip',
            'Connection': 'Keep-Alive'}


class Generate:
    def deviceId(self, data=None):
        if isinstance(data, str): data = bytes(data, 'utf-8')
        identifier = PREFIX + (data or os.urandom(20))
        mac = new(DEVICE_KEY, identifier, sha1)
        return f"{identifier.hex()}{mac.hexdigest()}".upper()

    def signature(self, data):
        data = data if isinstance(data, bytes) else data.encode("utf-8")
        return b64encode(PREFIX + new(SIG_KEY, data, sha1).digest()).decode("utf-8")


class Client:
    def __init__(self, proxies: str = None, deviceId: str = None):
        self.api = "https://service.narvii.com/api/v1"
        self.uid = None
        self.sid = None
        self.session = requests.Session()
        if proxies is not None:
            self.session.proxies = {"http": proxies,
                                    "https": proxies}
        else:
            pass
        if deviceId:
            self.deviceId = deviceId
        else:
            self.deviceId = Generate().deviceId()

    def __del__(self):
        try:
            self.session.close()
        except RuntimeError:
            self.session.close()

    def parse_headers(self, data=None, content_type=None, c=False):
        if c is False:
            return Headers(data=data, content_type=content_type, deviceId=self.deviceId, sid=self.sid).headers
        else:
            return Headers(data=data, content_type=content_type, deviceId=self.deviceId, sid=self.sid).postheaders

    def login(self, email: str, password: str):

        data = json.dumps({
            "email": email,
            "v": 2,
            "secret": f"0 {password}",
            "deviceID": self.deviceId,
            "clientType": 100,
            "action": "normal",
            "timestamp": int(time.time() * 1000)
        })
        with self.session.post(f"{self.api}/g/s/auth/login", headers=self.parse_headers(data=data),
                               data=data) as response:
            if response.status_code != 200:
                return response.status_code
            else:
                json_response = json.loads(response.text)
        self.sid = json_response["sid"]
        self.uid = json_response["account"]["uid"]
        return "OK"

    def register(self, nickname: str, email: str, password: str, verificationCode: str,
                 deviceId: str = Generate().deviceId()):
        data = json.dumps({
            "secret": f"0 {password}",
            "deviceID": deviceId,
            "email": email,
            "clientType": 100,
            "nickname": nickname,
            "latitude": 0,
            "longitude": 0,
            "address": None,
            "clientCallbackURL": "narviiapp://relogin",
            "validationContext": {
                "data": {
                    "code": verificationCode
                },
                "type": 1,
                "identity": email
            },
            "type": 1,
            "identity": email,
            "timestamp": int(time.time() * 1000)
        })

        response = self.session.post(f"{self.api}/g/s/auth/register", data=data, headers=self.parse_headers(data=data))
        if response.status_code != 200:
            return response.status_code
        else:
            return response.text

    def request_verify_code(self, email: str, resetPassword: bool = False):
        data = {
            "identity": email,
            "type": 1,
            "deviceID": self.deviceId
        }

        if resetPassword is True:
            data["level"] = 2
            data["purpose"] = "reset-password"

        data = json.dumps(data)
        response = self.session.post(f"{self.api}/g/s/auth/request-security-validation",
                                     headers=self.parse_headers(data=data), data=data)
        if response.status_code != 200:
            return response.status_code
        else:
            return response.text

    def get_account_info(self):
        response = self.session.get(f"{self.api}/g/s/account", headers=self.parse_headers())
        if response.status_code != 200:
            return response.text
        else:
            return json.loads(response.text)["account"]

    def get_wallet_info(self):
        response = self.session.get(f"{self.api}/g/s/wallet", headers=self.parse_headers())
        if response.status_code != 200:
            return response.text
        else:
            return json.loads(response.text)["wallet"]['totalCoins']

    def logout(self):

        data = json.dumps({
            "deviceID": self.deviceId,
            "clientType": 100,
            "timestamp": int(time.time() * 1000)
        })
        response = self.session.post(f"{self.api}/g/s/auth/logout", headers=self.parse_headers(data=data), data=data)
        if response.status_code != 200:
            return response.text
        return response.status_code

    def get_from_link(self, link: str):
        response = self.session.get(f"{self.api}/g/s/link-resolution?q={link}", headers=self.parse_headers())
        if response.status_code != 200:
            return response.text
        else:
            return json.loads(response.text)["linkInfoV2"]

    def join_community(self, comId: str, invitationId: str = None):

        data = {"timestamp": int(time.time() * 1000)}
        if invitationId:
            data["invitationId"] = invitationId

        data = json.dumps(data)
        response = self.session.post(f"{self.api}/x{comId}/s/community/join", data=data,
                                     headers=self.parse_headers(data=data, c=True))
        if response.status_code != 200:
            return response.text
        else:
            return response.status_code

    def send_active_obj(self, comId: str, tz: int = -time.timezone // 1000, timers: list = None):
        data = {"userActiveTimeChunkList": timers, "timestamp": int(time.time() * 1000), "optInAdsFlags": 2147483647,
                "timezone": tz}
        data = json_minify(json.dumps(data))

        with self.session.post(f"{self.api}/x{comId}/s/community/stats/user-active-time",
                               headers=self.parse_headers(data=data, c=True), data=data, timeout=600) as response:
            if response.status_code != 200:
                return response.text
            else:
                return response.status_code

    def send_coins(self, coins: int, comId, blogId: str = None, chatId: str = None, objectId: str = None,
                   transactionId: str = None):
        url = None
        if transactionId is None: transactionId = str(UUID(hexlify(os.urandom(16)).decode('ascii')))

        data = {
            "coins": coins,
            "tippingContext": {"transactionId": transactionId},
            "timestamp": int(time.time() * 1000)
        }

        if blogId is not None: url = f"{self.api}/x{comId}/s/blog/{blogId}/tipping"
        if chatId is not None: url = f"{self.api}/x{comId}/s/chat/thread/{chatId}/tipping"
        if objectId is not None:
            data["objectId"] = objectId
            data["objectType"] = 2
            url = f"{self.api}/x{comId}/s/tipping"

        data = json.dumps(data)
        response = self.session.post(url, headers=self.parse_headers(data=data, c=True), data=data)
        if response.status_code != 200:
            return response.text
        else:
            return response.status_code


def TZ():
    localhour = time.strftime("%H", time.gmtime())
    localminute = time.strftime("%M", time.gmtime())
    UTC = {"GMT0": '+0', "GMT1": '+60', "GMT2": '+120', "GMT3": '+180', "GMT4": '+240', "GMT5": '+300',
           "GMT6": '+360',
           "GMT7": '+420', "GMT8": '+480', "GMT9": '+540', "GMT10": '+600', "GMT11": '+660', "GMT12": '+720',
           "GMT13": '+780', "GMT-1": '-60', "GMT-2": '-120', "GMT-3": '-180', "GMT-4": '-240', "GMT-5": '-300',
           "GMT-6": '-360', "GMT-7": '-420', "GMT-8": '-480', "GMT-9": '-540', "GMT-10": '-600', "GMT-11": '-660'}
    hour = [localhour, localminute]
    if hour[0] == "00": tz = UTC["GMT-1"];return int(tz)
    if hour[0] == "01": tz = UTC["GMT-2"];return int(tz)
    if hour[0] == "02": tz = UTC["GMT-3"];return int(tz)
    if hour[0] == "03": tz = UTC["GMT-4"];return int(tz)
    if hour[0] == "04": tz = UTC["GMT-5"];return int(tz)
    if hour[0] == "05": tz = UTC["GMT-6"];return int(tz)
    if hour[0] == "06": tz = UTC["GMT-7"];return int(tz)
    if hour[0] == "07": tz = UTC["GMT-8"];return int(tz)
    if hour[0] == "08": tz = UTC["GMT-9"];return int(tz)
    if hour[0] == "09": tz = UTC["GMT-10"];return int(tz)
    if hour[0] == "10": tz = UTC["GMT13"];return int(tz)
    if hour[0] == "11": tz = UTC["GMT12"];return int(tz)
    if hour[0] == "12": tz = UTC["GMT11"];return int(tz)
    if hour[0] == "13": tz = UTC["GMT10"];return int(tz)
    if hour[0] == "14": tz = UTC["GMT9"];return int(tz)
    if hour[0] == "15": tz = UTC["GMT8"];return int(tz)
    if hour[0] == "16": tz = UTC["GMT7"];return int(tz)
    if hour[0] == "17": tz = UTC["GMT6"];return int(tz)
    if hour[0] == "18": tz = UTC["GMT5"];return int(tz)
    if hour[0] == "19": tz = UTC["GMT4"];return int(tz)
    if hour[0] == "20": tz = UTC["GMT3"];return int(tz)
    if hour[0] == "21": tz = UTC["GMT2"];return int(tz)
    if hour[0] == "22": tz = UTC["GMT1"];return int(tz)
    if hour[0] == "23": tz = UTC["GMT0"];return int(tz)


class ModeratorProcessor:
    def __init__(self, proxyName, accountsName, blog, length_box=None):
        self.recurs = False
        self.accounts = []
        self.passed_accounts = []
        self.proxyName, self.accountsName = proxyName, accountsName
        self.comId = None
        self.blogId = None
        self.linkInfo = None
        self.proxies = open(proxyName).read().split("\n")
        self.accounts = open(accountsName).read().split("\n")
        random.shuffle(self.accounts)
        self.session = requests.Session()
        self.blog = blog
        self.total_coins = 0

        self.box_accounts = []
        if length_box is None:
            self.box_len = len(self.proxies)
        else:
            self.box_len = length_box

    def load_info(self):
        print(f"Loaded {len(self.accounts)} accounts.\nLoaded {len(self.proxies)} proxy.")

    def getLink(self, client):
        try:
            self.linkInfo = client.get_from_link(self.blog)
            self.comId = self.linkInfo['extensions']['linkInfo']['ndcId']
            self.blogId = self.linkInfo['extensions']['linkInfo']['objectId']
        except Exception:
            self.getLink(client)

    def threadit(self, acc, pr):
        try:
            start = time.time()
            acc = acc.split()
            email, password, device = acc[0], acc[1], acc[2]
            client = Client(proxies=pr, deviceId=device)
            login = client.login(email, password)
            self.linkInfo = client.get_from_link(self.blog)
            self.getLink(client)
            client.join_community(self.comId)
            print(f"Farming: [{email}] Status: [{login}] Proxy:[{pr}] Time: [0 sec] start send_obj")
            for _ in range(1, 25):
                try:
                    client.send_active_obj(comId=self.comId,
                                           timers=[{'start': int(time.time()), 'end': int(time.time()) + 300} for _
                                                   in
                                                   range(50)],
                                           tz=TZ())
                    time.sleep(3.5)
                except requests.exceptions.ProxyError:
                    time.sleep(5)
                    break
                except Exception as e:
                    print(f"line 354: {e}")
            print(f"[{email}] end send_obj")
            coins = int(client.get_wallet_info())
            try:
                if coins > 500:

                    for _ in range(coins // 500):
                        client.send_coins(comId=self.comId, coins=500,
                                          blogId=self.blogId)
                elif coins == 0:
                    pass
                else:
                    s = client.send_coins(comId=self.comId, coins=coins, blogId=self.blogId)
                    if s == 200 or "200":
                        pass
                    else:
                        print(s)

                print(f"[{email}] coins send: {coins}")
            except Exception as e:
                print(f"line 374: {e}")
            print(
                f"Finish: [{email}] Time on account [{round(time.time() - start)} sec]")
            client.logout()
        except requests.exceptions.ProxyError:
            return 0
        except ValueError:
            print(f"value error")
        except requests.exceptions.ConnectTimeout:
            print(f'Error: proxy info [{pr}] timeout')
        except Exception as e:
            print(f"line 385: {e}")
            if e == "maximum recursion depth exceeded":
                pass

    def get_proxies(self):
        try:
            proxi = self.proxies[0]
            self.proxies.remove(proxi)
            if proxi is []:
                self.proxies = open(self.proxyName).read().split("\n")
                proxi = self.proxies[0]
            return proxi
        except IndexError:
            self.proxies = open(self.proxyName).read().split("\n")
            proxi = self.proxies[0]
            return proxi

    def box_farmer_start(self):
        try:
            random.shuffle(self.accounts)
            self.box_accounts = [self.accounts[i:i + self.box_len] for i in range(0, len(self.accounts), self.box_len)]
            for pack in self.box_accounts:
                box_farm = [Process(target=self.threadit, args=(acc, self.get_proxies())) for acc in pack]
                for t in box_farm:
                    t.start()
                    time.sleep(10)
                os.system('cls')
        except ValueError:
            print("Exit")
            exit()
        except ConnectionError:
            pass

    def admin(self):
        self.load_info()
        while True:
            self.box_farmer_start()
            if self.recurs is True:
                exit()
