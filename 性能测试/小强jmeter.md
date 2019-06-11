### 1. badboy功能  
1. 录制、回放  
2. 检查点  
3. 参数化 ${v_name}  
4. 步骤循环  
5. 数据库连接 Tools--DataSource  
6. 并发 Tools--Run Backgroud Threads  
7. 报告 view--report  
### 2. jmeter使用步骤  
1. 添加线程组，设置线程数、循环数  
2. 添加请求sample，设置请求地址、方法、参数  
3. 添加监听器，结果树、聚合报告  
### 3. jmeter参数化  
1. 添加--前置处理器--用户参数  
2. 添加--配置元件--CSV Data  
3. 选项--函数助手--生成随机数  
### 4. jmeter断言  
1. 响应断言  // 用来判断响应结果中是否包含某关键字  
2. 断言持续时间  // 用来判断响应时间时候在规定时间内  
3. 大小断言  // 用来判断响应体的数据包字节数大小  
### 5. 监控服务端资源(cpu,memory,I/O etc.)   
1. jmeter安装插件 [JMeterPlugins-Standard-x.x.x.zip](https://jmeter-plugins.org/downloads/old/)  
2. 服务端启动对应程序[PerfMon.zip](https://jmeter-plugins.org/wiki/PerfMon/)  
3. jmeter添加perfom metrics collector  
4. 其中选择需要监控的服务器资源   
注：Linux性能监控还可以使用nmon工具，[使用教程](https://blog.csdn.net/russ44/article/details/53081448)  






