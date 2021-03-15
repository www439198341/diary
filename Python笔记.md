### 1. Python导入导出第三方库  
[参考文档](https://blog.csdn.net/u014236259/article/details/78209321)
```
pip freeze > requirements.txt
pip install -r requirements.txt
```

### 2. virtualenvwrapper


### 3. python turtle。乌龟画图模块，自带。
```
import turtle
pen = turtle.Turtle()
......
turtle.done()
```
这里后续可以考虑做些课程

### 4. PyAutoGUI模块，模拟键鼠动作

### 5. tkinter模块，开发GUI

### 6. 8位16进制转小数类型
```
import binascii
import struct

h = '295c8fc2f528f03f'
value = str(struct.unpack('<d', binascii.unhexlify(h))[0])
# value = 1.01
```
