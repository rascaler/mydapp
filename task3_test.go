package mydapp

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	confirm "github.com/gagliardetto/solana-go/rpc/sendAndConfirmTransaction"
	"github.com/gagliardetto/solana-go/rpc/ws"
	"github.com/gagliardetto/solana-go/text"
)

var solclient = rpc.New(rpc.DevNet_RPC)
var solwsclient, _ = ws.Connect(context.Background(), rpc.DevNet_WS)
var solaccount1 = os.Getenv("SOL_ACCOUNT1")
var solaccount2 = os.Getenv("SOL_ACCOUNT2")
var solaccount1PrivateKey = os.Getenv("SOL_ACCOUNT1_PRIVATE_KEY")

//var wssclient, _ = ethclient.Dial(os.Getenv("SEPOLIA_WSS_URL"))
//var privateKey, _ = crypto.HexToECDSA(os.Getenv("PRIVATE_KEY"))

// 获取区块信息
func TestGetSolBlock(t *testing.T) {

	// 指定要查询的区块高度（例如最新区块减去 10）
	slot := uint64(369613842) // 替换为你想查询的 slot

	// 可选：设置配置选项（如是否返回交易详情等）
	rewards := true
	opts := rpc.GetBlockOpts{
		Encoding:           solana.EncodingBase64, // 或 jsonParsed 等
		TransactionDetails: rpc.TransactionDetailsFull,
		Rewards:            &rewards,
	}

	ctx := context.Background()

	// 获取区块
	block, err := solclient.GetBlockWithOpts(
		ctx,
		slot,
		&opts,
	)
	if err != nil {
		log.Fatalf("获取区块失败: %v", err)
	}

	// 打印区块基本信息
	fmt.Printf("区块 Slot: %d\n", block.Blockhash)
	fmt.Printf("父 Slot: %d\n", block.ParentSlot)
	fmt.Printf("区块哈希: %s\n", block.Blockhash)
	fmt.Printf("交易数量: %d\n", len(block.Transactions))

	// 如果需要，可以遍历交易
	//for i, tx := range block.Transactions {
	//	fmt.Printf("交易 #%d: %s\n", i, tx)
	//}

}

// 获取账户余额
func TestSolBalanceAt(t *testing.T) {
	// 2. 要查询的账户地址（替换为你自己的地址）
	pubKey, err := solana.PublicKeyFromBase58(solaccount1)
	if err != nil {
		log.Fatal("无效的公钥:", err)
	}

	// 3. 获取余额（单位：lamports）
	ctx := context.Background()
	balanceResp, err := solclient.GetBalance(ctx, pubKey, rpc.CommitmentMax)
	if err != nil {
		log.Fatal("获取余额失败:", err)
	}

	// 4. 转换为 SOL（可选）
	bigBalance, _ := new(big.Float).SetString(strconv.FormatUint(balanceResp.Value, 10))
	d, _ := new(big.Float).SetString(strconv.FormatUint(solana.LAMPORTS_PER_SOL, 10))
	fmt.Println("账户余额为：", new(big.Float).Quo(bigBalance, d))
}

// 转账交易
func TestSolTransaction(t *testing.T) {
	// 发送方私钥
	sender, err := solana.PrivateKeyFromBase58(solaccount1PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	// 接收方地址
	receiver, err := solana.PublicKeyFromBase58(solaccount2)
	if err != nil {
		log.Fatal(err)
	}

	// 4. 要转账的金额（单位：lamports，1 SOL = 1_000_000_000 lamports）
	amount := solana.LAMPORTS_PER_SOL / 10 // 转0.1
	// 5. 获取最新区块哈希（用于设置交易有效期）
	ctx := context.Background()
	recentBlockhash, err := solclient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		log.Fatal("获取区块哈希失败:", err)
	}

	// 构建交易
	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			system.NewTransferInstruction(
				amount,
				sender.PublicKey(),
				receiver,
			).Build(),
		},
		recentBlockhash.Value.Blockhash,
		solana.TransactionPayer(sender.PublicKey()),
	)
	if err != nil {
		log.Fatal("构建交易失败:", err)
	}

	_, err = tx.Sign(
		func(key solana.PublicKey) *solana.PrivateKey {
			if sender.PublicKey().Equals(key) {
				return &sender
			}
			return nil
		},
	)
	if err != nil {
		panic(fmt.Errorf("unable to sign transaction: %w", err))
	}
	spew.Dump(tx)

	tx.EncodeTree(text.NewTreeEncoder(os.Stdout, "Transfer SOL"))

	// Send transaction, and wait for confirmation:
	sig, err := confirm.SendAndConfirmTransaction(
		context.TODO(),
		solclient,
		solwsclient,
		tx,
	)
	if err != nil {
		log.Fatal(err)
	}
	spew.Dump(sig)
}

// 订阅账户变更
func TestSubScribe(t *testing.T) {
	// 使用 WebSocket 客户端（注意是 ws.New，不是 rpc.New）

	// 要监听的账户地址（例如一个 Token 账户或钱包）
	accountPubkey, err := solana.PublicKeyFromBase58(solaccount1)
	if err != nil {
		log.Fatal(err)
	}

	// 订阅账户
	sub, err := solwsclient.AccountSubscribe(
		accountPubkey,
		"confirmed", // 或 "finalized"
	)
	if err != nil {
		log.Fatal("订阅失败:", err)
	}
	defer sub.Unsubscribe()

	fmt.Println("✅ 正在监听账户变更...")

	// 持续接收通知
	for {
		msg, err := sub.Recv(context.Background())
		if err != nil {
			log.Println("接收消息出错:", err)
			break
		}

		// 打印账户数据（base64 编码）
		fmt.Printf("🔔 账户更新！Slot: %d\n", msg.Context.Slot)
		fmt.Printf("   Lamports: %d\n", msg.Value.Lamports)
		fmt.Printf("   Owner: %s\n", msg.Value.Owner)
		fmt.Printf("   Data 长度: %d 字节\n", len(msg.Value.Data.GetBinary()))
	}
}
