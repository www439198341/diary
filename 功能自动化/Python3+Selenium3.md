##### 1. 预期条件
```
from selenium.webdriver.support import expected_conditions as EC
```

##### 2. 等待
```
from selenium.webdriver.support.wait import WebDriverWait
```

##### 3. 生成随机字符串
```
import random
s = ramdom.sample('1234567890', 5)
# 该方法中第一个参数为随机字符串的全集，第二个参数为随机字符串的长度
# 此时返回结果为list类型
# list类型转str类型，方法如下
"".join(list)
```
    注1：[list和str互转参考](https://www.cnblogs.com/anningwang/p/7627117.html)<br>
    注2：random还可以生成随机数字等

##### 4. 验证码处理（万能码，cookie技术）：保存图片到本地，然后进行解析<br>
    调用在线收费识别接口[showapi](https://www.showapi.com/api/view/184/4)

##### 5. python读取配置文件
```
pip install Configparser
```
配置文件信息如下
```
# element.ini
[RegisterElement]
user_email=id>register_email
user_name=id>register_nickname
password=id>register_password
code_image=id>getcode_num
code_text=id>captcha_code
```
读取代码
```
# read_ini.py
import configparser
cf = configparser.ConfigParser()
cf.read('filename')
cf.get('RegisterElement', 'user_email')
```

##### 6. PO模型代码架构

```
graph TB
A[case]-->B[business]
B[business]-->C[handle]
A-->C
C[handle]-->D[util]
C[handle]-->E[conf]
C[handle]-->F[image]
C[handle]-->G[3rdAPI]
```
注：
   1. case层：输入测试数据，预期结果，调用方法进行对比
   2. business层：封装业务逻辑，通常是几个连贯步骤，实现一个单独功能，如注册、登陆、加购物车
   3. handle层：获取页面单一元素。应该把某一个页面的所有独立元素进行封装，可以通过配置文件方式进行元素定位
   4. util：公共方法
   5. conf：存放配置文件
   6. image：图片
   7. 3rdAPI：调用第三方接口


##### 7. unittest默认方法
   1. test开头的方法
   2. setUp(self)、tearDown(self)
   3. setUpClass(self)、tearDownClass(self)这两个方法需要装饰器@classmethod
   4. TestSuite()测试集
   5. case的执行顺序默认按照名字字母排序（不是自上而下），如果想改变默认顺序，需要将case有序添加到suite
   6. 跳过用例的装饰器@unittest.skip('xxx')
代码示例
```
import unittest

class TestProject(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        pass
    
    @classmethod
    def tearDownClass(self):
        pass
    
    def setUp(self):
        pass
    
    def tearDown(self):
        pass
    
    def test_case01(self):
        pass
    
    def test_case02(self):
        pass
    
if __name__ == '__main__':
    # unittest.main()
    suite = unittest.TestSuite()  # 创建suite实例
    suite.addTest(TestProject('test_case01'))  # 添加test case到suite
    unittest.TextTestRunner().run(suite)  # 执行suite
```

##### 8. unittest批量执行py文件
```
# 目录结构如下:
project
|__case
    |__run.py
    |__test01.py
    |__test02.py

# run.py
import unittest
import os

path = os.path.join(os.getcwd(), 'case')
suite = unittest.defaultTestLoader.discover(path, 'test*.py')
unittest.TextTestRunner().run(suite)

```

##### 9. 生成html测试报告（HtmlTestRunner）
HtmlTestRunner原作者使用python2版本，github上面fork了[其他作者改写的python3版本](https://github.com/www439198341/HTMLTestRunner_PY3)。使用方法：
```
下载HTMLTestRunner_PY3.py文件
改名后，复制到python/Lib目录

import unittest
import HTMLTestRunner
class MyTestClass(unittest.TestCase):
    # test case method
if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(MyTestClass('test case method name'))
    fp = open('report/my_report.html', 'wb')
    runner = HTMLTestRunner.HTMLTestRunner(
        stream=fp,
        title='My unit test',
        description='This demonstrates the report output by HTMLTestRunner.'
    )
    runner.STYLESHEET_TMPL = '<link rel="stylesheet" href="my_stylesheet.css" type="text/css">'
    runner.run(suite)
```
```
BeautifulReport界面比HTMLTestRunner更加友好，以后使用这个模板
result = BeautifulReport(suite)
result.report(file_name, description, log_path)
```

##### 10. case失败，自动截图
```
在tearDown(self)方法中进行处理
def tearDown(self):
    for method, error in self._outcome.errors:  # 遍历列表[(n1, n2), (n3, n4)]类型
        if error:
            name = self._testMethodName
            self.driver.save_screenshot(name)
```

##### 11. ddt模块，数据驱动（同样的测试步骤，采用不同数据进行测试，类似QTP里面DataTable参数化）。[参考文章](https://www.cnblogs.com/miniren/p/7099187.html)
```
# pip install ddt
# ddt可以读取json格式文件

import unittest
from ddt import ddt, data, unpack

@ddt
class MyTestCase1(unittest.TestCase):
    @data([1,2,3],[4,5,6],[7,7,8])
    @unpack  # 如果参数类型为列表等复杂类型，需要unpack，否则不需要
    def test_normal(self, a, b, c):
        self.assertEqual(a+b, c)
```

##### 12. xlrd模块，操作excel文件。[参考文章](https://blog.csdn.net/kevinelstri/article/details/52711006)
```
import xlrd

book = xlrd.open_workbook("file_path")
table = book.sheets()[0]
rows = table.nrows
cols = table.ncols
cell = table.cell(x,y)
value = cell.value
table.put_cell(row, col, 1, value, 0)
```

##### 13. 关键字驱动，keyword view，IDE
|操作|目标|数据|
|:---|:---|:---|
|打开浏览器|||
|输入url||url|
|输入值|username|'username'|

```
关键字写在excel等外部表格数据文件，格式如上；
工具包中，有方法或类，解析数据文件，调用相应方法；
方法实现；
project
|__dataDrivenTest.xls  # excel数据文件
|__util.py  # 解析excel文件
    |__if cell(row, col).value == '打开浏览器':
           open_browser()
       elif cell(row, col).value == '输入url'
           get_url()
       elif cell(row, col).value == 'others':
           pass

|__page_method.py  # 封装所有方法，打开浏览器，输入url，输入值，检查点等
    |__def open_browser()
    |__def get_url()
    |__def send_value()
|__run_case.py  # 主方法，传入excel文件
```

##### 14. 行为驱动。这东西不常用，也不顺手。感觉跟cucumber有点像。

##### 15. 日志模块。[参考文章](https://blog.csdn.net/langkew/article/details/51553549)
疑问：在工程根目录下，引包调用会报错。在包中调用，则不会报错。不知道为什么。




