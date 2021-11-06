#### 编译
##### 编译pcap
```
make pcap
```

#### 运行demo程序
默认使用轮询模式
```
./pcap ./data/1.pcap
./pcap ./data/1.pcap "(&(sport>2000)(&(!(sport=2140))(proto=udp)))"
./pcap ./data/1.pcap "(&(sip=200.*)(&(!(sport=2140))(proto=tcp)))"
```
第二个参数是pcap文件所在路径
第三个参数是pcap过滤的表达式
注意表达式用`()`包裹，里面可以包含多个条件
示列：筛选出源端口大于2000，且源端口不等于2140，且协议的udp的表项，支持字段sport, dport, sip, dsip, proto等，具体看demo程序里注册了多少相关的比较字段吧

#### 测试程序
```
make test
```

#### 清空编译产物
```
make clean
```