import json
import sys
import requests
import hashlib

virustotal_url = 'https://www.virustotal.com/vtapi/v2/file/report'
scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
api_key = '816ca7d873fd1e308e5b3054c4834866d2676f7258e823d8f6e80bdcea5548dd' # virust total public key



class Hasher:
    #text를 인코딩 하는 과정
    def __init__(self,TFpath):
        self.tstr = TFpath

    def strHash(self):
        text = self.tstr
        encoded_text = text.encode()
        enc = hashlib.sha256(encoded_text).hexdigest() #md5 , sha 1 ,sha256 , sha512 등등 존재 
        print('texthash : ',enc)
        return enc
    
    def filehash(self):
        f = open(self.tstr,'rb')
        data = f.read()
        f.close()
        Thash = hashlib.sha1(data).hexdigest()
        return Thash # 출력 시에 다음과 같이 특정 16진수 수로 변환됨 이를 통해 고유값 즉 무결성을 획득 가능.

class viruschecker: 
    def __init__(self,hashvalue,api_key) :
        self.Thashval = hashvalue
        self.key = api_key
    
    def checking(self):
        params = {'apikey': self.key, 'resource': self.Thashval} 
        response = requests.get(virustotal_url, params=params) # 해당 url로 param을 보낸 결과값을 가져오는 코드
        resultVal = response.json()
        typeofvirus = resultVal.get('scans',{})
        keys=typeofvirus.keys()
        Detecting_list = []
        for key in keys :
            if typeofvirus[key]['result'] != None:
                detect_list=[(key,typeofvirus[key]['result'])]
                Detecting_list.extend(detect_list)
        print(Detecting_list)
        count = resultVal.get('positives') # json 파일의 경우  key 값이 매칭이 되어있기 때문에 get을 통해 키 값과 매칭된 값을 가져올 수 있음.
        if count is None :
            print('not supported type of file')
            return False
        if int(count) < 5 : #fulse positives  == virus detected
            print('<it was not virus>')
            return False
        else :
            print('positives vaccine search:',count)
            print('<caution Maliciouscode has been detected>')
            return True

if __name__ == "__main__" :
    target = 'Unlocker1.9.2.exe'
    tup = Hasher(target).filehash()
    result = viruschecker(tup,api_key).checking()