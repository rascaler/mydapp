# 以太坊技术架构
## 1.分层应用
![Go Logo](/assets/2.png "dora the explore")
- 应用层：去中心化应用，如钱包，交易所，应用场景在金融，数字货币，身份认证，溯源等
- 合约层：封装各种脚本，合约等可执行程序，使得链上可编程，调用后触发交易
- 激励层：通过挖矿，交易手续费等激励，鼓励节点间参与记账，确保网络安全运行
- 共识层：该层允许高度分散的节点在P2P网络中对于区块数据的有效性达成一致，确定谁可以向主链中添加新的区块。
- 网络层：节点之间数据交换，包括P2P网络、数据传播和验证机制，P2P的特性，就算其中部分节点失效，也不会影响其他节点
- 数据层：区块数据存储，节点之间通过数据同步，每个节点都有相同的数据，常用数据库如leveldb

## 2.以太坊区块核心服务
![Go Logo](/assets/3.png "dora the explore")
## 3.go-ethereum解析
```
➜  go-ethereum :
.
├── accounts        // 以太坊的钱包和账户管理
    ├── abi         // 以太坊合约的ABI代码
    ├── keystore    // 支持 keystore 模式的钱包
    └── usbwallet   // 支持 USB 模式的钱包
├── bmt             // 二进制的 Merkle 树的实现
├── build           // 编译与构建的一些脚本和配置
├── cmd             // 命令行工具集
    ├── abigen      // ABI 生成器
    ├── bootnode    // 启动一个仅仅实现网络发现的节点
    ├── ethkey
    ├── evm         // 以太坊虚拟机的开发工具
    ├── faucet
    ├── geth        // geth 命令行工具
    ├── p2psim      // 提供了一个工具来模拟 HTTP 的 API
    ├── puppeth     // 创建一个新的以太坊网络的向导
    ├── rlpdump     // RLP 数据的格式化输出
    ├── swarm       // swarm 网络的接入点
    ├── utils       // 公共工具
    └── wnode       // 一个简单的 whisper 节点，可以用作独立的引导节点。此外，可以用于不同的测试和诊断目的
├── common          // 提供了一些公共通用的工具类
├── compression     // 压缩
├── consensus       // 提供了以太坊的一些共识算法，比如：ethhash
├── console         // 控制台
├── containers      // 支持 docker 和 vagrant 等容器
├── contracts       // 合约管理
├── core            // 核心数据结构和算法（EVM，state，Blockchain，布隆过滤器等）
├── crypto          // 加密相关
├── dashboard       // 
├── eth             // 在其中实现了以太坊的协议
├── ethclient       // geth 客户端入口
├── ethdb           // eth 的数据库（包括生产环境的leveldb和供测试用的内存数据库）
├── ethstats        // 提供以太坊网络状态的报告
├── event           // 用于处理实时事件
├── les             // 以太坊的轻量级协议子集(Light Ethereum Subprotocol)
├── light           // 实现为以太坊轻量级客户端提供按需检索的功能
├── log             // 日志模块
├── metrics         // 度量和检测
├── miner           // 提供以太坊的区块创建和挖矿
├── mobile          // 移动端的一些 wrapper
├── node            // 以太坊的多种类型的节点
├── p2p             // P2P 网络协议
├── params          // 参数管理
├── rlp             // 以太坊的序列化处理（rlp 递归长度前缀编码）
├── rpc             // rpc 远程方法调用
├── swarm           // swarm 网络存储和处理
├── trie            // 以太坊中的重要数据结构，Merkle Patricia Tries
└── whisper         // whisper 节点协议
```




