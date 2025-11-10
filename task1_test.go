package mydapp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	token "mydapp/abi"
	"mydapp/abi/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/sha3"
)

var err = godotenv.Load()
var client, _ = ethclient.Dial(os.Getenv("SEPOLIA_HTPP_URL"))
var wssclient, _ = ethclient.Dial(os.Getenv("SEPOLIA_WSS_URL"))
var privateKey, _ = crypto.HexToECDSA(os.Getenv("PRIVATE_KEY"))
var decimal = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil).String()

func TestKeyStore(t *testing.T) {
	// Read key from file.
	keyfilepath := filepath.Join(os.Getenv("HOME"), "Library/Ethereum/keystore/UTC--2025-11-02T04-31-55.426772000Z--902ada939d0e744809090bf3f1f1c53ae9284a49")
	keyjson, err := os.ReadFile(keyfilepath)
	if err != nil {
		utils.Fatalf("Failed to read the keyfile at '%s': %v", keyfilepath, err)
	}

	// Decrypt key with passphrase.
	passphrase := "Qing123"
	key, err := keystore.DecryptKey(keyjson, passphrase)
	if err != nil {
		utils.Fatalf("Error decrypting key: %v", err)
	}

	address := key.Address.Hex()
	privateKey := hex.EncodeToString(crypto.FromECDSA(key.PrivateKey))

	fmt.Println(fmt.Sprintf("address: %s,\nprivateKye: %s", address, privateKey))
}

// 获取区块
func TestGetBlock(t *testing.T) {
	// 返回最新区块
	header, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(header.Number.String())
}

// 查询交易
func TestGetTransaction(t *testing.T) {
	// 获取最新的区块
	block, err := client.BlockByNumber(context.Background(), big.NewInt(9552048))
	if err != nil {
		log.Fatal(err)
	}

	// 获取区块链id
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(block.Hash().String())
	for _, tx := range block.Transactions() {
		fmt.Println(tx.Hash().Hex())
		fmt.Println(tx.Value().String())
		if err != nil {
			log.Fatal(err)
		}

		if sender, err := types.Sender(types.NewEIP155Signer(chainId), tx); err == nil {
			fmt.Println("sender", sender.Hex()) // 0x0fD081e3Bb178dc45c0cb23202069ddA57064258
		}
		// 获取交易收据
		receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(receipt.Status) // 1
	}
}

// 查询收据
func TestGetTransactionReceipt(t *testing.T) {
	block, err := client.BlockByNumber(context.Background(), big.NewInt(9552048))
	if err != nil {
		log.Fatal(err)
	}
	receiptByHash, err := client.BlockReceipts(context.Background(), rpc.BlockNumberOrHashWithHash(block.Hash(), false))
	if err != nil {
		log.Fatal(err)
	}

	receiptsByNum, err := client.BlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(block.Number().Int64())))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(receiptByHash[0] == receiptsByNum[0]) // true

	for _, receipt := range receiptByHash {
		fmt.Println(receipt.Status)           // 1
		fmt.Println(receipt.Logs)             // []
		fmt.Println(receipt.TxHash.Hex())     // 0x20294a03e8766e9aeab58327fc4112756017c6c28f6f99c7722f4a29075601c5
		fmt.Println(receipt.TransactionIndex) // 0
	}
}

// 创建钱包
func TestAccount(t *testing.T) {
	// 生成随机私钥
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
		return
	}

	// 转换字节
	privateKeyBytes := crypto.FromECDSA(privateKey)

	// 转换16进制字符串
	fmt.Println(hex.EncodeToString(privateKeyBytes))
	// 带0x
	fmt.Println(hexutil.Encode(privateKeyBytes))

	//生成公钥
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
		return
	}

	// 抓换字节
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	//转换16进制，去掉0x04
	fmt.Println(hex.EncodeToString(publicKeyBytes)) // 不带0x
	fmt.Println(hexutil.Encode(publicKeyBytes))     // 带0x

	// 生成钱包地址方式1，EIP55格式
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	fmt.Println(address)

	// 生成钱包地址方式2，加密公钥，但是这种方式生成的不带EIP55效验，全部都是小写
	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])
	fmt.Println("full:", hexutil.Encode(hash.Sum(nil)[:]))
	fmt.Println(hexutil.Encode(hash.Sum(nil)[12:])) // 原长32位，截去12位，保留后20位
}

// 交易转账
func TestTransaction(t *testing.T) {
	// 交易准备
	// 1.转账账户
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	// metamask 地址 0x3165b4b27b04e651dbdfa9499d98ad5f9eab24cd
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Println(fromAddress.Hex()) // 大小写不一样

	// 2交易随机数
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}
	// 3.gas费用
	gasPrice, err := client.SuggestGasPrice(context.Background())
	gasLimit := uint64(21000) // ETH 转账标准 gas 用量

	// 4.目标账户
	toAddress := common.HexToAddress("0x94a76c513b08b9bd6dfc55a7cbbb19956a8296e4")
	// 5.转账金额0.01个eth
	value := big.NewInt(0.01 * 1e18)

	var data []byte // ETH 转账不需要 data
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gasLimit,
		To:       &toAddress,
		Value:    value,
		Data:     data,
	})

	// 6签名交易
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal("获取 chain ID 失败:", err)
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal("签名失败:", err)
	}
	//  7发送交易
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal("发送交易失败:", err)
	}

	fmt.Printf("交易已发送！Hash: %s\n", signedTx.Hash().Hex())

}

// 代币交易转账
func TestTokenTransaction(t *testing.T) {
	// 交易准备
	// 1.转账账户
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	// metamask 地址 0x3165b4b27b04e651dbdfa9499d98ad5f9eab24cd
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Println(fromAddress.Hex()) // 大小写不一样

	// 2交易随机数
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}
	// 3.gas费用
	gasPrice, err := client.SuggestGasPrice(context.Background())

	// 4.目标账户
	toAddress := common.HexToAddress("0x94a76c513b08b9bd6dfc55a7cbbb19956a8296e4")
	tokenAddress := common.HexToAddress("0xdcEF896be182fA52f1d5c0cE5E63422d5E9cb7Af")
	// 5.代币转账不需要eth
	value := big.NewInt(0)

	// 6.根据data数据协议组装data
	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]
	fmt.Println(hexutil.Encode(methodID)) // 0xa9059cbb
	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	fmt.Println(hexutil.Encode(paddedAddress)) // 0x0000000000000000000000004592d8f8d7b001e72cb26a73e4fa1806a51ac79d
	amount := new(big.Int)
	amount.SetString("1000000000000000000000", 10) // 1000 tokens
	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)
	fmt.Println(hexutil.Encode(paddedAmount)) // 0x00000000000000000000000000000000000000000000003635c9adc5dea00000
	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)
	fmt.Println(hexutil.Encode(data))

	// 根据执行内容计算gas
	gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		From: fromAddress,
		To:   &tokenAddress,
		Data: data,
	})
	gasLimit = gasLimit * 11 / 10
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(gasLimit)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gasLimit,
		To:       &tokenAddress,
		Value:    value,
		Data:     data,
	})

	// 6签名交易
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal("获取 chain ID 失败:", err)
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal("签名失败:", err)
	}
	//  7发送交易
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal("发送交易失败:", err)
	}

	fmt.Printf("交易已发送！Hash: %s\n", signedTx.Hash().Hex())

}

// 获取账户余额
func TestBalance(t *testing.T) {
	account := common.HexToAddress("0x94a76c513b08b9bd6dfc55a7cbbb19956a8296e4")
	balance, err := client.BalanceAt(context.Background(), account, nil)
	if err != nil {
		log.Fatal(err)
	}
	// 防止精度丢失，所有都要转为big类型再进行计算
	bigBalance, _ := new(big.Float).SetString(balance.String())
	d, _ := new(big.Float).SetString(decimal)
	//s := math.Pow10(18)
	//fmt.Println("账户余额为：", new(big.Float).Quo(bigBalance, new(big.Float).SetString()))
	fmt.Println("账户余额为：", new(big.Float).Quo(bigBalance, d))

	// 转账，再测试之前的区块
	blockNumber := big.NewInt(9590400)
	blockBalance, err := client.BalanceAt(context.Background(), account, blockNumber)
	if err != nil {
		log.Fatal(err)
	}

	bigBalance, _ = new(big.Float).SetString(blockBalance.String())
	fmt.Println("9590400区块账户余额为：", new(big.Float).Quo(bigBalance, d))

	// 获取待处理的账户余额，例如，在提交或等待交易确认后
	pendingbalance, err := client.PendingBalanceAt(context.Background(), account)
	if err != nil {
		log.Fatal(err)
	}
	bigPendingBalance, _ := new(big.Float).SetString(pendingbalance.String())
	fmt.Println("9590400区块账户余额为：", new(big.Float).Quo(bigPendingBalance, d))

}

// abi调用合约
func TestTokenContract(t *testing.T) {
	tokenAddress := common.HexToAddress("0xdcEF896be182fA52f1d5c0cE5E63422d5E9cb7Af")
	instance, err := token.NewToken(tokenAddress, client)
	if err != nil {
		log.Fatal(err)
	}
	name, err := instance.Name(&bind.CallOpts{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("name:", name)
	symbol, err := instance.Symbol(&bind.CallOpts{})
	if err != nil {
		log.Fatal(err)
	}
	decimals, err := instance.Decimals(&bind.CallOpts{})
	if err != nil {
		log.Fatal(err)
	}
	balance, err := instance.BalanceOf(&bind.CallOpts{}, common.HexToAddress("0x94a76c513b08b9bd6dfc55a7cbbb19956a8296e4"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("balance:", balance)
	fmt.Println("symbol:", symbol)
	fmt.Println("decimals:", decimals)
	fmt.Println("name:", name)
}

// 订阅区块
func TestSubscribeBlock(t *testing.T) {
	headers := make(chan *types.Header)
	sub, err := wssclient.SubscribeNewHead(context.Background(), headers)
	if err != nil {
		log.Fatal(err)
	}
	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case header := <-headers:
			fmt.Println("区块号：", header.Number.Uint64(), "，哈希：", header.Hash().Hex())
		}
	}
}

// 部署合约，abigen模式
// address 0x3432cBfd6622E18A2BE9A73ac6010B5bba1b1Ec7
// tx 0x9317a18f635d44628ddbee10bca5dcc8c7129e4279bed16dabc94b62ab8ef633
func TestDeployContract(t *testing.T) {
	// 交易准备
	// 1.转账账户
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	// metamask 地址 0x3165b4b27b04e651dbdfa9499d98ad5f9eab24cd
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Println(fromAddress.Hex()) // 大小写不一样

	// 2交易随机数
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	// 6签名交易
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal("获取 chain ID 失败:", err)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0) // in wei
	// 自动计算gas
	//auth.GasLimit = nil        // in units
	//auth.GasPrice = nil

	input := "1.0"
	address, tx, instance, err := store.DeployStore(auth, client, input)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(address.Hex())
	fmt.Println(tx.Hash().Hex())

	_ = instance
}

// 使用普通方式部署合约
// address 0xb2d0D780B38288640339C363537789A221756f7d
// tx 0x9919b85270d4cea2483ed95029f6c08222ee8cfd2527bfc40ff7b71d3fe34d0c
func TestDeployContract2(t *testing.T) {
	// 交易准备
	// 1.转账账户
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	// metamask 地址 0x3165b4b27b04e651dbdfa9499d98ad5f9eab24cd
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Println(fromAddress.Hex()) // 大小写不一样

	// 2交易随机数
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}
	// 3.gas费用
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// 4.目标账户
	//toAddress := common.HexToAddress("0x94a76c513b08b9bd6dfc55a7cbbb19956a8296e4")
	// 5.代币转账不需要eth
	//value := big.NewInt(0)
	bindata, err := os.ReadFile("./abi/store/store_sol_Store.bin")
	if err != nil {
		log.Fatal(err)
	}
	hexdata := string(bindata)
	bindata = common.FromHex("0x" + hexdata)
	// 构造函数有参数 需要合并构造函数中的abi字节码用于初始化调用
	abidata, err := os.ReadFile("./abi/store/store_sol_Store.abi")
	if err != nil {
		log.Fatal(err)
	}
	parsedABI, _ := abi.JSON(strings.NewReader(string(abidata)))
	args, err := parsedABI.Pack("", "1.0")
	if err != nil {
		log.Fatal(err)
	}
	data := append(bindata, args...)
	// 6.根据data数据协议组装data
	// 根据执行内容计算gas
	gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		From: fromAddress,
		To:   nil,
		Data: data,
	})
	if err != nil {
		log.Fatal(err)
	}

	//gasLimit = gasLimit * 11 / 10
	//if err != nil {
	//	log.Fatal(err)
	//}
	fmt.Println(gasLimit)
	//content := string(data) // 将 []byte 转为 string
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gasLimit,
		To:       nil,
		Value:    big.NewInt(0),
		Data:     data,
	})

	// 6签名交易
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal("获取 chain ID 失败:", err)
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal("签名失败:", err)
	}
	//  7发送交易
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal("发送交易失败:", err)
	}

	fmt.Printf("交易已发送！Hash: %s\n", signedTx.Hash().Hex())

	// 等待交易被挖矿
	receipt, err := waitForReceipt(client, signedTx.Hash())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Contract deployed at: %s\n", receipt.ContractAddress.Hex())
}

func waitForReceipt(client *ethclient.Client, txHash common.Hash) (*types.Receipt, error) {
	for {
		receipt, err := client.TransactionReceipt(context.Background(), txHash)
		if err == nil {
			return receipt, nil
		}
		if err != ethereum.NotFound {
			return nil, err
		}
		// 等待一段时间后再次查询
		time.Sleep(1 * time.Second)
	}
}

// 加载store合约
func TestLoadContract(t *testing.T) {
	storeContract, err := store.NewStore(common.HexToAddress("0xb2d0D780B38288640339C363537789A221756f7d"), client)
	if err != nil {
		log.Fatal(err)
	}
	// 获取版本
	version, err := storeContract.Version(&bind.CallOpts{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("version:", version)

	var key [32]byte
	var value [32]byte
	copy(key[:], []byte("qing"))
	copy(value[:], []byte("hello world"))
	// 构建一个交易
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal("获取 chain ID 失败:", err)
	}
	opt, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		log.Fatal(err)
	}
	tx, err := storeContract.SetItem(opt, key, value)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("tx hash:", tx.Hash().Hex())
	// 获取设置后的新值
	result, err := storeContract.Items(&bind.CallOpts{}, key)
	fmt.Println("result:", string(result[:])) // 有乱码
	fmt.Println("result:", string(bytes.TrimRight(result[:], "\x00")))
	_ = storeContract
}

// 查询事件
func TestQueryEvent(t *testing.T) {
	//9597041
	query := ethereum.FilterQuery{
		// BlockHash
		FromBlock: big.NewInt(9597041),
		// ToBlock:   big.NewInt(2394201),
		Addresses: []common.Address{
			common.HexToAddress("0xb2d0D780B38288640339C363537789A221756f7d"),
		},
		// Topics: [][]common.Hash{
		//  {},
		//  {},
		// },
	}
	logs, err := client.FilterLogs(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}

	// abi
	abidata, err := os.ReadFile("./abi/store/store_sol_Store.abi")
	if err != nil {
		log.Fatal(err)
	}
	parsedABI, _ := abi.JSON(strings.NewReader(string(abidata)))

	for _, l := range logs {
		fmt.Println(l.BlockHash.Hex())
		fmt.Println(l.BlockNumber)
		fmt.Println(l.TxHash.Hex())
		event := struct {
			Key   [32]byte
			Value [32]byte
		}{}
		err := parsedABI.UnpackIntoInterface(&event, "ItemSet", l.Data)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("event:key=", string(bytes.TrimRight(event.Key[:], "\x00")), ", value=", string(bytes.TrimRight(event.Value[:], "\x00")))
	}
}

// 订阅事件
func TestSubscribeEvent(t *testing.T) {
	query := ethereum.FilterQuery{
		Addresses: []common.Address{
			common.HexToAddress("0xb2d0D780B38288640339C363537789A221756f7d"),
		},
	}
	logs := make(chan types.Log)
	sub, err := wssclient.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		log.Fatal(err)
	}
	abidata, err := os.ReadFile("./abi/store/store_sol_Store.abi")
	if err != nil {
		log.Fatal(err)
	}
	parsedABI, _ := abi.JSON(strings.NewReader(string(abidata)))
	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case vLog := <-logs:
			fmt.Println(vLog.BlockHash.Hex())
			fmt.Println(vLog.BlockNumber)
			fmt.Println(vLog.TxHash.Hex())
			event := struct {
				Key   [32]byte
				Value [32]byte
			}{}
			err := parsedABI.UnpackIntoInterface(&event, "ItemSet", vLog.Data)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("event:key=", string(bytes.TrimRight(event.Key[:], "\x00")), ", value=", string(bytes.TrimRight(event.Value[:], "\x00")))
			var topics []string
			for i := range vLog.Topics {
				topics = append(topics, vLog.Topics[i].Hex())
			}
			fmt.Println("topics[0]=", topics[0])
			if len(topics) > 1 {
				fmt.Println("index topic:", topics[1:])
			}
		}
	}
}

//
//
//func TestFile(t *testing.T) {
//	data, err := os.ReadFile("./abi/store_sol_Store.bin")
//	if err != nil {
//		log.Fatal(err)
//	}
//	content := string(data) // 将 []byte 转为 string
//	fmt.Println("文件内容:")
//	fmt.Println(content)
//}

func TestEnv(t *testing.T) {
	fmt.Println(os.Getenv("APP_NAME"))
}
