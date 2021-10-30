#### 编译
##### 编译pcap
```
make pcap
```

#### 运行demo程序
默认使用轮询模式
```
./pcap ./data/1.pcap "(&(src_port>2000)(&(!(src_port=2140))(proto=udp)))"
```
第二个参数是pcap文件所在路径
第三个参数是pcap过滤的表达式
注意表达式用`()`包裹，里面可以包含多个条件
示列：筛选出源端口大于2000，且源端口不等于2140，且协议的udp的表项，支持字段src_port, dst_port, src_ip, dst_ip, proto