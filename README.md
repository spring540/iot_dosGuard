# 1、工具介绍
iot_dosGuard是一款面向IOT设备的流量捕获兼流量分析器，内置了基于轻量级机器学习方法的DDos检测模型，能够在极小的资源消耗的情况下实时监测针对设备发起的DDos攻击。
# 2、工具特点
- 抓包效率高。采用基于Linux内核库的高性能原始套接字（raw socket）技术组合：AF_PACKET + TPACKET_v3机制抓包。
- 开箱即用，零依赖运行。
- 内置基于机器学习（随机森林）的DDos检测算法。识别过程如下图所示，模型将流量按照时间切片，划分为一个个的流量窗口，将其作为最小分析对象。通过分析流量窗口中流量的分布特征，识别该窗口流量是否是DDos流量。
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0d5475f12de44e8d8eac8603dd1335a5.png)

- 流量分析效率高。数据帧L3、L4报文均为纯C代码手动实现。
# 3、用法
复制源码到设备，编译运行即可。若设备没有编译环境，可在其它资源充足的Linux系统中下载设备对应平台架构的SDK编译包，编译完复制到设备上运行即可。
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/7df2ecaacc844f8d84bb885b9d90a692.png)

-i指定抓包分析的网口。
-b指定工具用于缓存流量包的块数，每块128KB，该值越小占用内存资源越少，但也越容易丢包。
-m指定单个流量窗口内分析的最大包数量，默认5000
-t流量窗口时间长度，默认是1s，若设备所处的网络流量流动强度不高，可以适度增大该值。
当没有攻击发生时：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1f219d60cab34354ac3f3f4bf5694f80.png)
当SYN_FLOOD发生时：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/c6528c31eee3441aabe5cff447544689.png)
除了SYN_FLOOD外，模型还支持"ACK_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "IGMP_FLOOD", "IP_FLOOD"5类DDos攻击，以及“PORTSCAN"扫描型攻击。
