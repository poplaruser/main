import base64
import json
import requests
from Crypto.Cipher import AES
import datetime
import copy
#增加注销

SECRET_KEY = 'kijjghdsjhf23456'  # 此处16|24|32个字符

class LsApi(object):
    # 作业发送
    def work(self):
        #测试环境
        url = "http://114.215.129.119:9000/ls-api/api/v1/it/work"
        #正式环境
        # url = "https://open.allynav.cn/api/api/v1/it/work"

        data = {
            "uuid": "91883e3ded56e520",
            "sn": "1220902996",
            "msg_time": 1712727107000,
            "begin_ts": 1712727107000,
            "end_ts": 1712729922000,
            "job_equip": "test-这是机器001",
            "area": 958.00878,
            "width": 2.3,
            "w_type": 1016,
            "c_type": 0,
            "w_h": 20.98908,
            "w_m": 30.9788,
            "work_sn": "2403301139-2074216",
            "workname": "test_work1-2403301139",
            "e_lat": 36.760148,
            "e_lon": 114.170952,
            "s_lat": 36.759897,
            "s_lon": 114.170616,
            "quality": {},
            "version": "1.3.199",
            "location": "中国上海",
            "attr": 24
        }
        # 去除空格
        en_data = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        # 数据加密
        aes_encrypt = AesEncrypt()
        encrypt_data = aes_encrypt.encrypt(en_data).strip("'")
        self._send(url, encrypt_data)

    # 轨迹发送
    def track(self):
        #测试环境
        url = "http://114.215.129.119:9000/ls-api/api/v1/it/pos"
        #正式环境
        # url = "https://open.allynav.cn/api/api/v1/it/pos"
        data = {
            "uuid": "91883e3ded56e520",
            "sn": "1220902996",
            "lon": 121.307467,
            "lat": 31.162116,
            "speed": 3.890,
            "h": 4.2403,
            "atz": 4.37,
            "diff": 4,
            "sv": 37,
            "state": 1,
            "attr": 24,
            "msg_time": 1703661555000,
            "job": {
                "type": 1016,
                "crop": 0,
                "work_sn": "2403301139-2074216",
                "width": 2.3,
                "workname": "test_work1-2403301139",
                "detail": {
                    "D1501": "99999",
                    "D1502": "22.098"
                }
            },
            "condition": {},
            "version": "1.4.32(test1)",
            "sou": 1,
            "lack_seed": {
                "i1": "1",
                "i2": "2",
                "i3": 600.45,
                "i4": "0|1|1|0|0"
            }
        }


        json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        # 获取模拟数据文件
        with open( "TrackAnaDataTbox.json" ) as file:
            jsonData = json.load(file)
        length = len(jsonData)

        # 获取当前时间
        current_time = datetime.datetime.now()
        #获取提前10分钟的时间
        delay_time = datetime.timedelta(minutes=-10)
        begin = current_time + delay_time
        # 设置间隔时间
        delta = datetime.timedelta(seconds=5)
        timeCount = length
        # 获取指定数量的时间戳
        for index in range(timeCount):
            date = begin
            # print(date.strftime("%Y-%m-%d %H:%M:%S"), date.timestamp(), int(round(date.timestamp() * 1000)))
            begin += delta
            # 时间戳赋值
            data['msg_time'] = int(round(date.timestamp() * 1000))
            # 作业名赋值
            job = data['job']
            job['workname'] = "test_work" + str(data['msg_time']) + "-1322061107"
            # 经纬度、速度、高程赋值
            data['lon'] = jsonData[index]['lo']
            data['lat'] = jsonData[index]['di']
            data['speed'] = jsonData[index]['sp']
            data['atz'] = jsonData[index]['alt']

            if index == 0:
                AnadataFirst = copy.deepcopy(data)
            if index == timeCount -1 :
                AnadataEnd = copy.deepcopy(data)

            # 去除空格
            en_data = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
            # 数据加密
            aes_encrypt = AesEncrypt()
            encrypt_data = aes_encrypt.encrypt(en_data).strip("'")
            self._send(url, encrypt_data)

        return AnadataFirst,AnadataEnd

    # 发送
    def _send(self, url, encrypt_data):
        req = {
            "username": "lsdh001",
            "password": "admin123",
            "para": encrypt_data
        }
        resp = requests.post(url, data=req)
        print("发送数据")
        print(resp.json())


class AesEncrypt(object):
    def __init__(self):
        self.key = SECRET_KEY
        self.mode = AES.MODE_ECB

    def pading(self, text):
        """对加密字符的处理"""
        return text + (len(self.key) - len(text) % len(self.key)) * chr(len(self.key) - len(text) % len(self.key))

    def unpading(self, text):
        """对解密字符的处理"""
        return text[0:-ord(text[-1:])]

    def getKey(self, key):
        """对key的处理,key 的长度 16，24，32"""
        key_len = len(key)
        if key_len <= 16:
            key += "0" * (16 - key_len)
        elif 16 < key_len <= 24:
            key += "0" * (24 - key_len)
        elif key_len <= 32:
            key += "0" * (32 - key_len)
        else:
            key = key[:32]
        return key

    # 加密函数
    def encrypt(self, text):
        cryptor = AES.new(self.key.encode("utf-8"), self.mode)  # ECB 模式
        self.ciphertext = cryptor.encrypt(bytes(self.pading(text), encoding="utf8"))
        encrypt_string = str(base64.b64encode(self.ciphertext)).lstrip("b")
        return encrypt_string

    # 解密函数
    def decrypt(self, text):
        decode = base64.b64decode(text)
        cryptor = AES.new(self.key.encode("utf8"), self.mode)  # ECB 模式
        plain_text = cryptor.decrypt(decode)
        decrypt_string = str(self.unpading(plain_text)).lstrip("b")
        return decrypt_string


if __name__ == '__main__':
    ls_api = LsApi()
    # ls_api.track()
    ls_api.work()



