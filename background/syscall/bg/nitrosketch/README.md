## Sketches for Exp#1

Subset1 includes CountMin, CountSketch, FlowRadar, UnivMon, ElasticSketch, SketchLearn

### Pktextracter

---

#### 构造函数

不需要任何参数。

#### 必要的成员变量/函数

1. `extract_form_file(char * fname, struct fiveTuple_t * fiveTupleFuf, u_int64_t n)`：从文件名为`fname`的 pcap 文件中，提取前`n`个数据包的五元组，存储在`fiveTupleFuf`数组中。

2. struct fiveTuple_t

   ```c++
   struct fiveTuple_t
   {//数据报五元组
       u_int8_t srcIP[4];            //源IP地址
       u_int8_t dstIP[4];            //目的IP地址
       u_int8_t protocol;            //协议类型
       u_int8_t srcPort[2];          //源端口号16bit
       u_int8_t dstPort[2];          //目的端口号16bit
       u_char str[13];               //所有字段集合
   };
   ```

3. 五元组格式（Ideal 类中给出了两种格式互相转换的方法）

   ```c++
   u_char format:
   
   eg : u_char * data
   
   content: |<-- srcIP -->| |<-- dstIP -->| |<- protype> ->| |<-srcPort->| |<-dstPort->|
    index : [0] [1] [2] [3] [4] [5] [6] [7]       [8]           [9] [10]     [11] [12]
    
   string format:
   
   eg : "100.123.247.122 111.205.25.237 17 60151 8080"
   
   format : "srcIP dstIP protype srcPort dstPort"
   ```

   

### Ideal

---

#### 构造函数

不需要任何参数。

#### 必要的成员变量/函数

1. `dict`：hash map，实现每流存储，key 为 string 型五元组，val 为其对应流的数据包个数；
2. `five_tuple_to_string(u_char * data)`： u_char 型五元组转化为字符串型；
3. `string_to_five_tuple(string str, u_char * data)`：`2`的互逆操作（string 转 u_char）， u_char 型五元组存储在`data`中；

4. `update(u_char * data, u_int64_t val)`：插入 u_char 型五元组`data`，数量为`val`（一般都是1）；
5. `query(u_char * data)`：查询 u_char 型五元组`data`对应流大小（实际意义是数据包个数）。



### MV-Sketch

---

#### 构造函数

`MVsketch(int a, int b)`：

- `a`：MV-Sketch矩阵的行数；
- `b`：MV-Sketch矩阵的列数；

#### 必要的成员变量/函数

1. `update(u_char * data, u_int64_t val)`：插入 u_char 型五元组`data`，数量为`val`（一般都是1）；
2. `query(u_char * data)`：查询 u_char 型五元组`data`对应流大小（实际意义是数据包个数）。



### FlowRadar

---

#### 构造函数

`FlowRadar(u_int64_t total_in_bytes, u_int64_t bf_k, u_int64_t ct_k)`：

- `total_in_bytes`：FlowRadar 所占字节数，可以用来确定 BloomFilter 和 CountingTable 的大小；
- `bf_k`：BloomFilter 的哈希函数个数；
- `ct_k`：CountingTable 的哈希函数个数。

#### 必要的成员变量/函数

1. `update(u_char * data)`：插入 u_char 型五元组`data`；
2. `dump(unordered_map<string, long long int> &res)`：获取 FlowRadar 中的所有流量信息，存放在`res`中。给出 string 格式的五元组，获得它对应流的数据包数量。



### ElasticSketch

---

#### 构造函数

`ElasticSketch(uint64_t size, u_int64_t lamada, u_int64_t m, u_int64_t n)`：

- `size`：HeavyPart 数组大小；
- `lamada`：HeavyPart 中的 λ 值；
- `m`：ElasticSketch 的行数；
- `n`：ElasticSketch 的列数。

#### 必要的成员变量/函数

1. `update(u_char * data)`：插入 u_char 型五元组`data`；
2. `query(u_char * data)`：查询 u_char 型五元组`data`对应流大小（实际意义是数据包个数）。
