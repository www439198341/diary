### Python处理RSA加解密问题

#### 1. RSA公钥私钥格式问题
```
Java
MIIEvgIBADANBgkghkiG9w....

Python
b'-----BEGIN PUBLIC KEY------\nMIIEvgIBADANBgkghkiG9w....\n-----END PUBLIC KEY-----\n'
b'----BEGIN RSA PRIVATE KEY-----\nXXXXX\n-----END RSA PRIVATE KEY-----\n'

区别：
需要在前后加上这种格式。
```
#### 2. 第三方模块
```
pycryptodome==3.8.2
```
#### 3. 引包
```
import base64
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5
```
#### 4. 定义公私钥
```
rsa_private_key = b'-----BEGIN ... KEY-----\n'
rsa_public_key = b'-----BEGIN ... KEY-----\n'
```
#### 5. 加解密
```
def jiami(message):
    public = RSA.importKey(rsa_public_key)
    cipher = Cipher_pkcs1_v1_5.new(public)
    cipher_text = base64.b64encode(cipher.encrypt(message))
    return cipher_text

def jiemi(cipher_text):
    private = RSA.importKey(rsa_private_key)
    cipher = Cipher_pkcs1_v1_5.new(private)
    text = cipher.decrypt(base64.b64decode(cipyer_text), None)
    return text.decode('utf8')
    
def qianming(private, message):
    random_generator = Random.new().read
    signer = PKCS1_v1_5.new(private)
    digest = MD5.new()
    digest.update(message)
    sign = signer.sign(digest)
    return base64.b64encode(sign)
```
#### 6. 总结，填坑。
6.1 网上主流答案用的是pycrypto这个库，但是这个库已经弃用了。一帮SB跟着复制粘贴，然而并不好用。  
6.2 衍生库有好几个，这方面介绍比较少。我也找到了pycryptodome这个库，但是被前面坑怕了。  
6.3 java配置文件中用的公私钥是单纯的字符串，而python库需要读入带格式的二进制串，在如何对公私钥进行格式转换这块是知识盲区。不知道从哪下手。  


