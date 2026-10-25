---
name: 'challenge-blockchain-web3'
description: 'HTB 区块链/Web3 题打法:先读 Setup.isSolved 逆推目标状态→按 pragma 版本分派漏洞类(0.7 找溢出/回绕,0.8+ 找鉴权/签名/存储)→Foundry cast 或 web3.py 构造交易→/flag 取旗。含 HTB 区块链内容地图(Track 73 十题 + Lazarus + Cyber Apocalypse + Business CTF 2024 迁移题 724/725/726)、Labs 容器实战接入链(container/start→多端口辨别 RPC vs 菜单式 TCP vs Web 提示页→eth_accounts 解锁账户免签名→challenge/own 提交)、合约源码与附件获取法(zip 口令 hackthebox)、逐题根因锚与 encodePacked 打包碰撞/编译元数据与 NatSpec 泄露(eth_getCode→CBOR→IPFS CID)/ecc 可塑性/WOTS/diamond 等新面。（检索词：blockchain/web3/solidity/ethereum/EVM/smart contract/smart-contract/智能合约/区块链/重入/reentrancy/整数溢出/整数下溢/underflow/overflow/tx.origin/访问控制/ECDSA/签名可塑性/signature malleability/ecrecover/ecrecover 复用/EIP-712/EIP-2535/diamond/diamondCut/delegatecall/存储槽/storage slot/WOTS/XMSS/一次性签名/one-time signature/metamorphic/变质合约/foundry/cast/anvil/forge/hardhat/web3.py/cyber apocalypse/hackenproof/intro to blockchain/isSolved/loot/Setup.sol/取 flag/abi.encodePacked/encodePacked/打包碰撞/hash collision/signature forgery/签名伪造/NotADemocraticElection/724/MetaVault/725/Brokenswap/726/Lucky-Faucet/Lucky Faucet/684/int64/uint64/int64→uint64/回绕/underflow/setBounds/sendRandomETH/LuckyFaucet/container/start/containerable_id/play_info/challenge own/x-ratelimit/token 401/metadata/元数据/NatSpec/CBOR/IPFS/CID/base58/eth_getCode/selfdestruct/emergency/VAULT_SECRET_K256/solc --metadata/sourcify/Don-t-Trust-Verify）'
whenToUse: 'HTB 遇到 Blockchain 类目题（Intro to Blockchain Track 的 10 题 / Lazarus - Rewind / Cyber Apocalypse 的 blockchain 类目 / Business CTF 迁移的 retired 题如 724）时：手上有 Setup.sol + TARGET 合约 + RPC 端点（Labs 容器或 CTF 附件），要把 TARGET 打空或夺取某个状态变量。也用于"要不要开区块链题/去哪儿找这类题/怎么把 Labs 容器开起来取连接信息"。'
metadata: { domain: web3, tier: T2 }
---

# HTB 区块链 / Web3 题 playbook

> 沉淀来源：Track 73「Intro to Blockchain」全 10 题的**官方附件源码**（逐题下载解压，非二手转述）+ 6 题公开 WP 交叉验证 + Cyber Apocalypse 2024/2025/2026 官方仓库。逐题证据与来源见工作区 `htb-challenge-wps/intro-to-blockchain/`。

## 0. HTB 的 Web3 内容地图（决定去哪找题）

| 位置 | 内容 | 规模 |
|---|---|---|
| Labs Track **73「Intro to Blockchain」**（= HackenProof Track，官方 Easy，2023-06 上线） | 10 题 | api 可查：`GET /api/v4/tracks/73` |
| Labs **Blockchain 类目**（活跃题池） | 8 题 | `challenge_category_id == 12` |
| Cyber Apocalypse 年度赛 | 每届 3~5 题 | 官方 repo `hackthebox/cyber-apocalypse*` |
| CTF 平台 | pack「Blockchain Exploitation – Essentials」 | 入门 |

🔴 **两个口径不等价，必须并集**：
- Track 里有 **3 道已 retired 的题**（500 Survival of the Fittest、526 Confidentiality、527 Funds Secured），
  而 `/api/v4/challenge/list`（只返活跃题）**看不到它们** → 只查类目会少算 3 题。
- 类目里的新题 **`Lazarus - Rewind 1`（id 1338, Hard, 2026-08）不在 Track 里**。
- ⇒ **权威集合 = Track 73（10 题） ∪ 类目新题（1338） ∪ retired 迁移题（724 NotADemocraticElection）**。
  Track 名是 "Intro to Blockchain"，不叫 "HackenProof Track"（那是官方博客口径）。

**源码/附件获取**（本卡最省时的一步）：`GET /api/v4/challenge/download/{id}`（Bearer token）→ 加密 zip，
**口令 `hackthebox`**（⚠️ 不是 Sherlock 附件的 `hacktheblue`）；`Expand-Archive` 不支持口令，必须 7z。
详见 `htb-challenge-wps/intro-to-blockchain/sources/README.md`。

🔴 **Labs 上还有一批 Business CTF 2024 迁移题（活跃题池里查不到，均 `retired=true`）** —— 已核实 3 道：

| id | 题 | 难度 | solves | 根因一句话 |
|---|---|---|---|---|
| **724** | NotADemocraticElection | Easy | 155 | `abi.encodePacked` 打包碰撞（§4.13） |
| **725** | MetaVault | Easy | 133 | 编译元数据 / NatSpec 泄露口令（§4.14） |
| **726** | Brokenswap | Medium | 74 | 尚未做 |

（Business CTF 2024 原始 `blockchain/` 目录还有第 4 道 `Recruitment [Very Easy]`，但 Labs 上按名字查 **404** —— 未迁移。）
`/api/v4/challenge/list` 只返活跃题，所以这三道全查不到（与上文"两个口径"是同一个坑）；
但 **retired 不影响开容器**，实测 `POST /api/v4/container/start` 对 724/725 都成功。
⇒ 按**名字**直接问 `/api/v4/challenge/info/<name>` 拿 id，比翻列表可靠（列表分页参数 `per_page`/`page` 实测不可靠，会重复返回同一页）。

### 0.1 HTB Labs 实战接入链（容器版 —— 与 CTF 附件完全不同的取数路径）

```text
① 拿 token    浏览器 localStorage['htb-token']（见下方 "token 坑"）
② 开容器      POST /api/v4/container/start   body {"containerable_id":<challenge_id>}
              → {"message":"Instance Created!","id":<container_id>}
              查状态：GET /api/v4/challenge/info/<name> → challenge.play_info.{status,ip,ports,expires_at}
③ 认端口      🔴 **端口数不固定**（724 是 2 个、725 是 3 个），逐个认，别假设：
              · JSON-RPC：POST http://IP:PORT/ 直接可用（eth_chainId → 0x7a69 = 31337，
                web3_clientVersion → anvil/v0.2.0）；/rpc 与 /jsonrpc 都是 404，**根路径就是 RPC**
              · 菜单式 TCP 服务（裸 socket，不是 HTTP）：
                "1 - Connection information / 2 - Restart Instance / 3 - Get flag" → "action? "
                选 1 得 Private key / Address / Target contract / Setup contract；选 3 得 flag
              · 🆕 **Web 前端**（725 有，724 没有）：返回 HTML 而不是 JSON-RPC，往往是**题面提示通道** ——
                725 的页面直接写着 "Don't Trust, Verify"，正文点名"代码编译时启用了 metadata 并发布到 IPFS"，
                等于把解法方向摆出来了。**每次开局都把每个端口用浏览器/curl 看一眼**，别只认 RPC 那一个。
              ⚠️ 认端口的判据：Invoke-WebRequest 报 **"服务器提交了协议冲突 Section=ResponseStatusLine"**、
                curl 报 **"Received HTTP/0.9 when not allowed"** 的那个端口就是菜单端口 → 改用 TcpClient / nc
              ⚠️ GET http://IP:PORT/flag 走 HTTP 是 **401**，flag 只能从菜单端口取
④ 打          web3.py（见 §5）
⑤ 交          POST /api/v4/challenge/own  body {"challenge_id":<id>,"flag":"HTB{...}"} → {"message":"Congratulations!"}
```

🔴 **`eth_accounts` 里通常直接躺着玩家地址 ⇒ 玩家账户在 anvil 上是解锁的**（实测返回
`["0xf407a12f…","0xc39846cb…"]`，第二个正是菜单给的玩家地址）。⇒ **可以 `eth_sendTransaction` 直接发交易，
完全不需要私钥 / 签名 / `build_transaction` + `sign_transaction` 流程** —— 菜单给的 Private key 只是备用。
省掉的这一整段正是新手最容易卡住的地方（本题全程零签名）。

🔴 **开新容器会顶掉旧容器（端口整批换新）**：724 与 725 的 `play_info.ip` **恰好**都是 `154.57.164.65`
（端口 724: 30326/30294 → 725: 30701/31732/32093），但 **684 换成了 `154.57.164.73`**
⇒ **IP 不一定复用，别把"同 IP"当规律**（我一度据 724/725 写成规律，当场被 684 推翻）。
可确定的是**旧实例随新实例创建被回收**：**别指望两个挑战容器并存**，也别拿旧端口继续打。

🔴 **玩家余额可能很宽裕**（725 的 anvil 账户带 **5000 ETH**，724 只有 1 ETH）⇒ 不要用"钱不够"去否掉某条思路，
先 `eth_getBalance` 看一眼。

🔴 **token 坑（PowerShell 侧 401 的头号原因）**：`htb-token` 是 988 字符的 JWT，**中转/手抄时错一个字符就 401**
（本会话实测就是把 `1VwYLX8` 抄成了 `1VwXLX8`）。两个规避法：
① **所有 API 调用都放在浏览器上下文里做**（`browser_evaluate` 内 `fetch(..., {headers:{Authorization:'Bearer '+localStorage['htb-token']}})`）——
   认证与 CORS 天然正确；② 非要落盘就 `Get-Content token.txt -Raw` 读，**绝不再手打**。
另：`labs.hackthebox.com` 限流 **15 次/窗口**（响应头 `x-ratelimit-limit: 15`），连打几次 list 就 429，别拿它当枚举工具刷。

## 1. 开局三步（固定顺序，别从题面叙事入手）

1. **读 `Setup.sol` 的 `isSolved()`** —— 这是唯一的判据，先逆推"要写哪个状态变量"，再回头看 TARGET。
   判据只有三种形态：
   - `address(TARGET).balance == 0` → 掏空（500/501/506/508/527）
   - 某状态变量被改写 → 夺取（502 `mapHolder`、505 `solver`、506 `keyOwner`、504 `viewItem(2).owner`、526 `balanceOf(player)`）
   - mapping 某键为 true（507 `isPortalActive["orcKingdom"]`）
2. **看 `pragma`** —— 这一条决定攻击面方向，杠杆最高：

   | pragma | 方向 | 题例 |
   |---|---|---|
   | `^0.7.0`（0.8 之前，**无溢出检查**） | 算术溢出/下溢、`uint32/uint64` 计数器回绕 | 504、506 |
   | `>=0.8` | 溢出已被语言层堵死 → 转 **鉴权语义 / 签名 / 随机数 / 存储与代理** | 500、501、502、505、507、508、526、527、1338 |

3. **flag 不在合约里** —— 满足 `isSolved` 后向 `GET /flag` 取（HTB 前端那个像素风按钮通常**不发交易**，纯装饰）。

> 玩家侧通常拿到：RPC 端点（`http://IP:PORT/rpc`）、玩家私钥、Setup 地址、`isSolved` 判据；
> 有时**只给 Setup 地址**，内部合约地址要自己用 CREATE 公式推导（504 就是）。

## 2. 判断信号表（看到源码里的什么，就去查什么）

| 源码信号 | 攻击面 | 题 |
|---|---|---|
| `require(fromBalance - amount >= 0)` （uint 上的减法恒真） | 恒真死代码 + 下溢，余额回绕成 2^256 级巨值 | 504 |
| 同一函数里出现 `tx.origin` 参与判断 | `tx.origin` 钓鱼：任何中间合约都满足 `tx.origin != msg.sender` | 501 |
| 构造函数用 `blockhash(...)` / `block.timestamp` / 公开变量派生"密钥" | 链上可预测：攻击合约在同一笔交易里原样复刻派生逻辑即可算出 | 502 |
| 成功/失败走不同 event，或失败 event 带 `%5` 这类**取不到的值** | 事件侧信道：从历史 log 里捞出成功那次交易，calldata 里有明文 | 505 |
| 先 `call{value:...}`（外部调用）再写黑名单/标志位 | 违反 CEI → 重入（攻击者在回调里趁自己未被拉黑再操作） | 506、1338 |
| `uint32/uint64` 计数器 + 累加（`timeout += YEAR`） | 整数回绕绕过时间锁 | 506 |
| 把**签名原始字节**存进数组当"已用过"判据 + `ecrecover` | **ECDSA 可塑性**：(r, n−s, v⊕1) 换一套字节、同一签名人 → 绕过重放保护 | 526 |
| 循环体里 `require`，但循环边界是入参（`signatures.length`） | **空数组/短数组绕过整段校验** | 527 |
| `delegatecall` 到固定地址；被调合约与本体存储槽布局相似 | 存储上下文混淆（代码是别人的，存储是自己的） | 507 |
| 用户名/owner 是 `string` 且用 `users[owner]` 当口令比较 | **未注册的 owner → `users[owner] == ""` → 空口令即通过**；`getLocker` 允许抢注任意用户名 | 508 |
| `create2` + 临时 init code + `selfdestruct` | **变质合约（metamorphic）**：同一地址可换 runtime 代码 | 1338 |
| 一次性签名（WOTS/XMSS）+ 链回滚/重组端点 | 一次性签名复用 → 同 leaf 双签 → 链上可前推伪造 | 1338 |
| `ecrecover` 只查 `sig.length`，不查 `s` 低阶与 `v ∈ {27,28}` | 签名可塑性（同上）+ 低 `s` 未归一 | 1338 |
| `abi.encodePacked(a, b)` 的结果**当签名/唯一键**用（`mapping(bytes => ...)`） | **打包碰撞**：`(name,surname)` 任意切分都拼出同一串 → 唯一性校验按 `(name,surname)` 走、权重按**拼接串**走 → 盗用他人权重/身份 | **724** |
| 硬编码一个 `bytes32` hash 当口令校验，注释里写"明文口令见某处 / 发布前会删掉" | **编译元数据泄露**：`eth_getCode` 尾部的 CBOR 里就有 IPFS CID → 拉回元数据 JSON，`output.devdoc` 里正是 NatSpec 原文（口令本体） | **725** |
| 题面/前端出现 `verify` / `open source` / `metadata` / `Don't Trust, Verify` / `IPFS` 等字样 | 同上一行（**设计者在指路**，web 端口那页就是提示） | 725 |

## 3. 决策树

```
读 Setup.isSolved + 全部源码 + pragma
├─ pragma < 0.8 ？
│  ├─ 判据涉及余额/记账 → 找 uint 下溢（504 型：transfer 路径 vs transferFrom 路径要分别读）
│  └─ 判据涉及时间/计数 → 找 uint32/uint64 回绕（506 型）
├─ pragma >= 0.8
│  ├─ 判据 = 余额归零
│  │  ├─ 参数完全没有上下界 → 一击斩杀（500：strongAttack(20) 恰好 = lifePoints）
│  │  ├─ 有"失衡/特殊条件"分支 → 读它的判据式（501：tx.origin != msg.sender）
│  │  ├─ 鉴权靠一个硬编码 hash/口令 → 先翻**编译元数据与 NatSpec**（725），再想爆破
│  │  ├─ 有外部调用在状态写入前 → CEI/重入（506、1338）
│  │  └─ 有循环内 require → 空数组绕过（527）
│  ├─ 判据 = 夺取某状态变量
│  │  ├─ 鉴权只靠一个可复制的等式 → 密钥派生可预测（502）/ 事件侧信道（505）
│  │  ├─ 鉴权靠签名 → 可塑性（526）/ 明文在链上（505）
│  │  ├─ 身份/权重由一个"拼接出来的 bytes 键"决定（`abi.encodePacked`）→ 打包碰撞盗用身份（724）
│  │  └─ 鉴权靠"用户名口令" → 空口令/抢注（508）
│  └─ 涉及代理/delegatecall/多分面 → 存储槽混淆（507）/ 未受控升级（1338）
└─ 需要"合约身份"或回调才能过判据 → 必须写攻击合约（cast send 到 EOA 无效）
```

## 4. 逐题细节锚（13 题，含官方源码级根因）

### 4.1 参数未校验：一击斩杀 —— 500 Survival of the Fittest（Very Easy, retired）
- 判据 `address(TARGET).balance == 0`；TARGET 只带 **10 wei**（构造时的那 1 ether 在 Setup 里）。
- `Creature.strongAttack(uint256 _damage)` 无鉴权无上限；`_dealDamage` = `lifePoints -= _damage`，`lifePoints` 初始 **20**。
- ⇒ `strongAttack(20)` → `loot()`（无鉴权）。
- 🔴 **不是下溢**：`^0.8.13` 下传 `type(uint256).max` 会 revert。必须精确 20。

### 4.2 `tx.origin` 鉴权 —— 501 Distract and Destroy（Very Easy）
- `lifePoints` 初始 1000；`attack()`：`if (aggro == address(0)) aggro = msg.sender;`
  `if (_isOffBalance() && aggro != msg.sender) lifePoints -= _damage;`
- `_isOffBalance() => tx.origin != msg.sender` ⇒ **必须由"合约"发起**。
- ⇒ 两步：① EOA 先调一次 `attack(0)` 把 `aggro` 占成自己；② 由攻击合约调 `attack(1000)` → `loot()`。
- 🔴 同一 `msg.sender` 连打两次伤害恒为 0（第二次 `aggro == msg.sender`）。

### 4.3 链上可预测"密钥" —— 502 Magic Vault（Easy）
- 判据 `TARGET.mapHolder() != address(TARGET)` —— **光 `unlock()` 不算通关，必须再调 `claimContent()`**。
- `unlock(bytes16)` 三条 require 是**同一 128 位的分段约束**，不是三个独立口令：
  - Case2：低 64 位 == `_secretKey`；Case3：高 64 位 == `uint64(uint160(owner))`；
  - Case1：整体 ≠ secret ⇒ 高 64 位非零。⇒ 口令 = `[owner 低 64 位 | secret 64 位]`。
- `owner` 是**部署 Vault 的 Setup 合约**（不是玩家）；`passphrase` 用 `blockhash(block.timestamp)` ⇒ 恒为
  `blockhash` 的零值（timestamp 远超最近 256 块窗口）⇒ **常量、零熵**；`_generateKey` 的输入全是公开/可现读的。
- ⇒ 攻击合约**照抄** `_generateKey`/`_magicPassword`，先 `nonce = target.nonce()` 对齐计数，再 `unlock(拼接值)`。
- 🔴 不读 `nonce()` 直接算必错；`bytes8→bytes16` 是右补零、`bytes16→bytes8` 取前 8 字节，容易写反。

### 4.4 恒真边界检查 + 下溢 —— 504 Token to Wonderland（Easy）
- 判据 `Shop.viewItem(2).owner == player`（index 2 = Golden Key，价 25_000_000）。
- `SilverCoin._transfer`：`require(fromBalance - amount >= 0)` 在 `uint256` 上**恒真** ⇒ 死代码 ⇒ `transfer` 可下溢。
- 🔴 **只有 `transfer()` 这条路**：`transferFrom()` 走的是 `_transferFrom`，那里写的是正确的 `require(fromBalance >= amount)`。
- ⇒ 先 `transfer(self, 25_000_100)` 把余额撑爆 → **`approve(shop, ≥ price)`** → `buyItem(2)`。
- 🔴 第一次 `buyItem` 会 revert `ERC20: insufficient allowance`：`transferFrom` 花的是**玩家→Shop** 的授权。
- 🔴 SilverCoin 地址未公开，需用 CREATE 推导：`keccak256(0xd6,0x94, setupAddr, 0x01)` 取低 20 字节。

### 4.5 链上取证（不破密码学）—— 505 Honor Among Thieves（Easy）
- `talk(bytes32 _key)`：`_flag = _key ^ encryptedFlag`，命中 `keccak256(abi.encode(_flag)) == hashedFlag` 才设 `solver`。
- 成功分支 `emit Voice(5)`；失败分支 `emit Voice(block.timestamp % 5)` —— **`%5` 永远取不到 5**。
- ⇒ 用 topic0+topic1 过滤历史 log，找 `severity == 5` 的那条交易，**它的 calldata 里就是明文 `_key`**，
  直接 `cast send $TARGET <raw input>` 重放。
- 🔴 `cast logs` 不带 topic 过滤会回吐海量事件；`severity` 是 `indexed`（在 topics[1]，不用解码 data）。
- ⚠️ 前提：`solver()` 已被别人设过（即链上已存在"成功那一次"）。新实例/无人解过时此路不通。

### 4.6 CEI 违反 + 计数器回绕 —— 506 False Bidding（Medium）
- 判据 `TARGET.keyOwner() == player`。三处缺陷叠加：
  1. `withdrawFromAuction()` **先 `bidders.pop()` + 外部 `call{value: bid/2}`，之后**才 `blacklisted[...] = true`
     ⇒ 攻击合约在 `receive()` 回调里趁自己未被拉黑**重新出价**，同一合约反复 bid→withdraw。
  2. `timeout` 是 `uint32`，每次出价 `timeout += YEAR(31556926)`，0.7 无溢出检查 ⇒ **累加 n 次回绕到极小值**，
     `require(block.timestamp > timeout)` 提前成立。`n = ceil((2^32 − timeout_now) / YEAR)`。
  3. `claimPrize()` 把 key 给 `topBidder().addr` = **攻击合约地址**，不是玩家 → 还要 `keyTransfer(player)`。
- 🔴 `_isPayable(msg.sender)` 会对你的合约做一次**0 值 call**，等于在出价判定中先回调你一次；`receive()` 必须
  区分 `msg.value == 0`，否则计数错乱/无限递归。
- 🔴 不能直接用 EOA 当攻击者（`blacklisted[tx.origin]` 也会置位，且 EOA 无法重入）；由外层合约 `new` 出的新地址才干净。
- 经济账：出价要 ≥ 2× 最高价；`pop()` 后最高价回落到底仓 0.5 ether ⇒ 每轮净耗 0.5 ether（30 ether 刚好够 ~15 轮）。
  🔴 次数**必须按实例的 `timeout()` 现算**，抄 WP 的 15 会错。

### 4.7 `delegatecall` + 存储槽混淆 —— 507 Portal Noncense（Medium）
- 判据 `TARGET.isPortalActive("orcKingdom")`（构造时只把 `elfKingdom` 置 true）。
- 唯一写入点两个：`requestPortal`（要 `isExpertStandby == true` —— **无 setter、默认 false**；且 `msg.value > 1337 ether`）
  和 `createPortal` 的 `destinations[_destination].delegatecall("connect()")`。
- ⇒ 入口只能是 `createPortal`：**delegatecall 让"目的地合约"的代码在 PortalStation 的存储上下文里执行**。
- 🔴 **关键在题名的 nonce**：三个目的地地址不是随便写的，而是**可预测的 CREATE 地址**（`(deployer, nonce)` 推导）。
  玩家**用自己的账户反复部署攻击合约**（每次 `forge create` 让 nonce +1），直到新合约地址**恰好等于**某个目的地地址
  ⇒ 那个"目的地"就变成了攻击者的代码。
  PortalStation 槽位 = `destinations`(0) / `isPortalActive`(1) / `isExpertStandby`(2)，攻击合约只要**复刻同一布局**
  并让 `connect()` 里写 `isPortalActive["orcKingdom"] = true`，delegatecall 时写的就是**PortalStation 自己的 slot1**。
- ⇒ 手法：① `cast compute-address <你的地址> --nonce <i>` 遍历（WP 脚本 `range(1,1000)`）找出能命中目的地的 nonce；
  ② 循环 `forge create` 把非命中次数的部署"刷"过去（WP 实测约 131 次）；③ `createPortal("orcKingdom")`。
- 🔴 **CREATE2 是死路**：论坛有人试遍合约名/hash salt/明文 salt/不同 bytecode 都匹配不上 —— 考的是 **CREATE + nonce**。
- 🔴 delegatecall 到 EOA 会 success 但返回空 ⇒ `abi.decode(retValue,(bool))` revert，所以 `connect()` **必须返回 `true`**。
- 参考值（该实例）：deployer `0xaDb67e10Fa330db49e98201B4c5F19356CfA3f59`，目的地 `0xFC31cde4…e4007`(orc) /
  `0x598136Fd…D4cF`(elf) / `0xFc2D16b5…8bf1`(dawrf，源码拼写如此)。

### 4.8 用户名空间与资产 owner 空间不隔离 —— 508 Locked and Loaded（Medium）
- 判据 `address(TARGET).balance == 0`（合约带 2 ether）。价格表：Common 1 / Rare 10 / Epic 100 / **Mythic 1e18**。
- 三条缺陷叠加（2 篇独立 WP 一致）：
  1. **经典重入（CEI 违背）**：`sellItem` 先 `usernameToWallet[prevOwner].call{value: price[rarity]}("")` 付款，
     **之后**才 `delete items[index]` ⇒ 攻击合约在 `receive()` 里再调 `sellItem`，反复领钱。
  2. **`private` 不是保护**：`users`（用户名→口令）只是 ABI 层不可见。两条独立读取路径：
     ⓐ `cast storage` 逐槽 dump —— `slot3 = items.length`，数组基址 `keccak256(abi.encode(3))`，
     mapping 项基址 `keccak256(abi.encodePacked(user, uint256(slot)))`；**口令 >32 字节时跨两槽，长度在末槽最后一字节**
     （实例里是 `0x51`=81 字节）；ⓑ `cast block 1` + `cast tx <hash>` 读**构造函数 calldata** ——
     用户名/口令成对按序排在里面，直接抠出来。
  3. **黑白名单逼你走重入**：`putItem` 有 `require(rarity < 3)` ⇒ **不能自铸 Mythic**（唯一值得抽干的档位，单价 1e18），
     只能去偷现成的 Mythic 道具；`getLocker` 把用户名 `"Vendor"` 拉黑。
  另有授权缺陷：`transferItem` 只校验"**当前 owner 的口令**"，不校验调用者身份 ⇒ 口令一到手就能把道具转给自己。
- ⇒ 完整链：偷口令 → `getLocker(自己的地址字符串, 自定口令)` → `transferItem("WizardsScepter", 自己, 偷来的口令)`
  → `sellItem` 触发重入并在 `receive()` 里循环领钱。
- 🔴 **重入必须自带终止条件**（`if (address(TARGET).balance > 100)`）：余额排空后再迭代一次会因
  `require(success)` 失败而整体回滚 —— 合约反而"保护"了自己（Kara 原话）。
- 🔴 `sellItem` 里 `_item.owner = "Vendor"` 改的是 **memory 副本**，对存储无效；循环**不 break**，`index` 取**最后一个**同名物品。
- 实例取值（⚠️ 随实例/版本可能不同，用前先 dump）：道具 `WizardsScepter`(Mythic)，owner `beliefspace`，
  口令 `ss4#Nq7nNyKMfZ=XESnOzP2hk:SSRCzo2QPk4w~~`（两篇 WP 独立取到同一串）。

### 4.9 ECDSA 可塑性绕过重放保护 —— 526 Confidentiality（Medium, retired）
- 判据 `TARGET.balanceOf(player) > 0`。`AccessToken.safeMintWithSignature(signature, to)`：
  `_verifySignature` 用 `ecrecover(approvalHash, v, r, s)`（approvalHash 是**常量**，无 nonce）；
  防重放靠 `usedSignatures[]` 数组比 `keccak256(签名原始字节)`。
- ⇒ **签名可塑性**：ECDSA 的 `(r, s, v)` 与 `(r, n−s, v⊕1)` 是**同一个签名人、内容等价**但**字节不同**的两份签名
  ⇒ `keccak256(_signature)` 不等 ⇒ 绕过 `_isSignatureUsed` ⇒ **重复铸造**。
- 签名从哪来：`Setup` 构造时自己调了一次 `safeMintWithSignature(signature, address(this))` ⇒
  **那份签名就在部署交易的 calldata 里**（公开可读）。
- `deconstructSignature` 用 `r=word0, s=word1, v=word2 的首字节`，即格式 `abi.encodePacked(r,s,v)`（65 字节）——
  变换时保持这个布局。合约**自带** `deconstructSignature`/`constructSignature`，直接 `cast call` 它们，别手写解析。
- ⇒ 步骤：① 取原签名（`cast call $TARGET 'usedSignatures(uint)(bytes)' 0`，或 `cast block 1`+`cast tx` 从
  Setup 部署交易的 calldata 末尾抠 65 字节 —— 两条路互为备用）；② 拆出 `(v,r,s)`；
  ③ `s' = n − s`，`v' = 27 ↔ 28`（取另一侧即可，两篇 WP 一个得 27 一个得 28）；
  ④ `constructSignature(v', r, s')` → ⑤ `safeMintWithSignature(newSig, myAddr)`。
  其中 `n = 115792089237316195423570985008687907852837564279074904382605163141518161494337`（secp256k1 阶）。
- 🔴 不能走 `safeMint(address)`（`onlyOwner`，owner 是另一个地址 ≠ 玩家）。
- 🔴 常见误诊：这不是"nonce 复用/k 恢复"，**不需要**恢复任何私钥 —— 只是同一签名的另一种合法编码。
- ⚠️ 同类：用签名字节本身做"已用"判据的实现**一律**可被可塑性绕过；正解是存 `keccak256(digest)` 或
  存 `(signer, nonce)` 并把 `s` 归一到低半区（EIP-2）。

### 4.10 校验写在循环体里 = 空数组绕过 —— 527 Funds Secured（Easy, retired）
- 判据 `address(TARGET).balance == 0`；Setup 给众筹合约打了 **1100 ether**。
- `CouncilWallet.closeCampaign(bytes[] signatures, address to, address payable crowdfundingContract)`：
  `for (i = 0; i < signatures.length; i++) { ...require(signer != 0 / 是理事会成员 / 不重复)... if (i > 5) break; }`
  —— **所有校验都在循环体内**。注释写 "at least 6 signatures"，但代码里**没有任何下界 require**。
- ⇒ 传**空数组 `[]`** → 循环 0 次 → 直接 `Crowdfunding.closeCampaign(to)`；而 `msg.sender == CouncilWallet`
  正是 `Crowdfunding.owner` ⇒ `selfdestruct(payable(to))` 把 1100 ether 全转走。
- 🔴 传 ≥7 个签名反而会在 `voters[i]` 越界 panic（`voters` 长 6，赋值在 break 之前）⇒ 只能是 0 个或 ≤6 个。
- ⚠️ 理事会成员是 `address(uint160(i))`（i=0..10），其中 index 0 = `address(0)` 被 `signer != 0` 拦下，
  1~10 无对应私钥 ⇒ 伪造签名不可行，空数组是唯一路径。
- 🔴 `selfdestruct` 在 Cancun(EIP-6780) 后不再删代码但**仍会转走余额**，判据照样成立。

### 4.11 2026 Hard：diamond + EIP-712 + WOTS + 变质反欺诈 —— 1338 Lazarus - Rewind 1（Hard）
> ⚠️ **无公开 WP**（截至调研日）。以下为**官方附件源码**逐文件分析，与题面叙事对齐；标 🔷 的是我的推论，不是已验证的解。

- 题干：`/connection` 给 RPC + 玩家账户 + 已部署地址（custody `diamond`、`metamorphic_antifraud`、`factory`、
  `guardian_address`、`xmss_root`/`pub_seed`）；`/flag` 在金库清空后可用。
- **双签门槛**：每次出金要 **①冷签名机的 XMSS/WOTS+ 一次性签名 ②guardian 反欺诈 bot 的 ECDSA 联签**，
  两者都针对**同一个 EIP-712 提现摘要**（`Withdrawal(address to,uint256 amount,uint256 leafIndex,bytes32 salt)`，
  domain `VantageRollup`/`1`/chainid/verifyingContract）。
- 结构：EIP-2535 **Diamond**（`DiamondCutFacet.diamondCut` 仅 owner；`WithdrawFacet`）+ 固定槽存储
  （`keccak256("vantage.rollup.vault.storage")`）+ `WotsVerifier`（W=16、67 条链、Merkle authPath）+
  `MetamorphicFactory`（CREATE2 + 临时 init code + `selfdestruct` 可换 runtime）+ `AntiFraudV1`（恒 true）/
  `AntiFraudV2`（`amount <= dailyLimit`）。
- 源码里**确实存在**的攻击面（🔷 存在性可证，是否即预期解未验证）：
  1. **反欺诈是变质合约**：`assertOk` 是外部调用，而该地址的 runtime **可被替换**（V1 恒 true 就在源码里）
     ⇒ dailyLimit 可绕过。
  2. **CEI 违反**：`withdraw()` 的顺序是 `usedLeaf 检查 → guardian 校验 → IAntiFraud(...).assertOk(...)
     → WOTS 校验 → 才写 usedLeaf` ⇒ `assertOk` 这次外部调用**发生在状态写入之前**
     ⇒ 若 antiFraud 可换成自己的代码，可**重入同一 leafIndex** → 同一份签名双花。
  3. **一次性签名 + `/reorg`**：`usedLeaf[leafIndex]` 是唯一防重放；而 `/reorg`（sequencer backup/restore）
     🔷 可回滚该状态 ⇒ 同一 WOTS leaf 复用 ⇒ 一次性签名性质被破坏。
  4. **guardian 侧**：README 明确写出 oracle 发的是 **biased-nonce attestation**（且是 domain-separated 心跳、
     不是提现签名）⇒ 🔷 思路是收集 `/guardian/issued` 的若干签名，用 **ECDSA nonce 偏差 + 格（HNP/LLL）**
     恢复 guardian 私钥，再对任意提现摘要自行签名。
  5. **`_recover` 的宽松校验**：只查 `sig.length == 65`，`if (v < 27) v += 27;`，**未校验 `s` 是否 ≤ n/2**（EIP-2）
     ⇒ 可塑性面与 526 同源。
  6. `WotsVerifier.verify` 不校验 `authPath` 长度/`leafIndex` 范围 🔷（但 root 固定，仍需有效路径）。
- 🔴 **不要照抄社区单源说法**：LinkedIn 上有帖子称预期解是"owner 用了 Anvil 默认测试私钥 + `diamondCut`
  注入 `drain()`" —— 该说法**无第二来源、且与官方附件的代码结构不符**（附件里没有 `drain()`，owner 也不是
  附件能决定的东西）。标 ⚠️ 待验证。
- 工具坑：`foundry.toml` 钉 `solc 0.8.28` + `evm_version = "shanghai"`；本地复现要用同一版本。
- 同一系列的 **Lazarus - Rewind 2（id 1365）是 Quantum Crypto / Reverse**，**技术面不同**，别互相套用。

### 4.12 Cyber Apocalypse 分册（CA2024/2025/2026 官方 repo + CA2023 公开 WP 来源）

⚠️ **引用前提**：**官方 repo 只有三个**（`cyber-apocalypse-2024` / `-2025` / `-ctf-2026`），且**只提交 `README.md` + `htb/solver.py`**，
**挑战合约本体不在仓库里**（例外：CA2026 三题有利用侧代码 —— `Caldrin's Day Away/htb/Exploit.sol` 是真实可编译的攻击合约、
`Second Stamp/htb/solver/solver.py`、`The Far Orchard/htb/solver/src/main.rs`）。所以"官方 objective"来自 README 文本。
🔴 **CA2023 没有对应官方 repo**：下表 2023 两题（Navigating the Unknown / Shooting 101）的判据与根因来自**公开第三方 WP**，
与 2024–2026 的「官方 repo 一手来源」**证据等级不同**，引用时别混同（flag 真实性另见本节末段）。

| 届 | 题 | 判据 | 根因（一句话） |
|---|---|---|---|
| 2023 | Navigating the Unknown | `TARGET.updated()` | 无访问控制的置位函数 + 硬编码魔法值（`updateSensors(10)`） |
| 2023 | Shooting 101 | 三个布尔全 true | **状态机顺序靠 `fallback`(非空 calldata) vs `receive`(空 calldata) 的触发差异分割**，三步不可颠倒 |
| 2024 | Russian Roulette | `TARGET.balance == 0`（带 10 ether） | **弱随机**：`blockhash(block.number-1) % 10 == 7` 命中即 `selfdestruct` ⇒ 循环重试（期望 ~10 次）。`0.8.23` **早于 Cancun** ⇒ 真的删代码+转余额 |
| 2024 | Recovery | **无合约判据**（纯链下） | 被拿下的主机上**助记词明文残留**；🔴 **Electrum seed ≠ BIP39**，必须用 Electrum 客户端 + regtest 恢复 |
| 2024 | Lucky Faucet | ✅ **2026-09-29 实战确认**（原标"官方未给 Setup，判据未确证"）：**Labs 实例里 Setup 是存在的**（有地址、`isSolved()` 可调，只是官方 repo 不放源码）。🔴 实例实测 **玩家起始就有 5000 ETH，而 `isSolved()` 仍是 False** ⇒ 判据**不是"余额 ≥ 10 ETH"而是"增量 ≥ 10 ETH"**（README 里那句"we require at least 10 ETH to solve"是**口语表述，与链上实现不等价**）；faucet 初始 **500 ETH**，一次调用后 `isSolved()==True` | `setBounds(int64,int64)` **只约束上界**（两条 `require` 都是 `<=` 正数上限，负数天然满足）；`0.7.6` 下把负 `int64` cast 成 `uint64` 会回绕 ⇒ 取 `lower=-2, upper=-1` 使 `randomInt % 2 - 2 ∈ {-2,-1}` → `uint64(2^64−2)` / `uint64(2^64−1)` ≈ **18.44 ETH**，一次到手。🔴 **参数顺序是 `(lower, upper)`**：`cast send ... "setBounds(int64,int64)" -- -2 -1`（原生 cast 传负数要 `--` 分隔）；web3.py 直接 `setBounds(-2, -1)` 即可（签名是 `int64`，无需手搓补码） |
| 2025 | Eldorion | `TARGET.isDefeated()`（`health==0`） | 回血修饰符用 **严格大于** `block.timestamp > lastAttackTimestamp` ⇒ **同一笔交易内批量调用共享 timestamp**，首次写入后条件恒假 ⇒ 回血失效；`require(health >= damage)` 使超杀被拒 ⇒ 只能 3×100。**必须由合约发起** |
| 2025 | HeliosDEX | `player.balance >= 20 ether`（判玩家 EOA！） | **舍入方向不对称**：三种 swap 传 OZ `Rounding` 0/1/**3(Expand 永远向上)**，反向赎回用默认 Floor ⇒ 买入向上卖出向下 = 稳定套利。`trade_cost = 10**17 + 1`（**+1 wei 就是制造小数部分的开关**）；MAL 只 1.5×不够、**HLS 2×才够 20 门槛** ← 刻意的分水岭 |
| 2025 | EldoriaGate | `checkUsperer(player)` → `authenticated && rolesBitMask==0`（**非 view，要发交易**） | 🔴 **内联汇编里的 uint8 环绕 + 溢出检查在 256 位域失效**：① 0.8 的溢出检查**不覆盖 `assembly`**；② `if lt(roles, defaultRolesMask)` 是 256 位比较，抓不到 uint8 环绕；③ 回绕发生在 `shl(8,roles)` 打包之后，`and(shr(8,packed),0xff)` 读回得 0。触发 `msg.value = 255`。次级：`bytes4 private` 只是 ABI 层，`eth_getStorageAt` 直读 |
| 2026 | Caldrin's Day Away | `balanceOf(sharehouse) < 150_000e6` | **"已批准的调用"其返回值仍可被操纵**：`readStampedOrder` 校验的是 **calldata 哈希**（批准的是"调用"不是"返回值"），而该调用返回 AMM 现货储备 ⇒ 闪电贷拉盘 → `recountHoldings`（**任何人可调**）→ `redeemClaim` 超赔。四步原子化（借→拉盘→重估→赎回→换回→还贷） |
| 2026 | Second Stamp | 8 个余额参数**全部**低于残留上限 | **Sui Move 包升级谱系跨版本状态机断裂**（见下） |
| 2026 | The Far Orchard | `honoredCount()==8 && honoredBitmap()==0xff` | **Halo2 电路 variable-base 标量乘的底点未锚定** ⇒ 可对任意目标叶子伪造 ZK 证明（见下） |

**🔴 2026 的三个新面（库内此前完全空白，值得单独立卡）**

1. **Sui Move 包升级谱系**（Second Stamp）
   - 三要素：① 包升级**保留同一 package ID**，**旧版本入口默认仍可调用**（除非 UpgradeCap policy 收紧）；
     ② `versioned::new` 恒初始化 `version = 1`，而 `assert_supported` 只断言 `version <= SUPPORTED_VERSION`
     ⇒ **`Versioned{version:1}` 同时通过 v1/v2/v3 三版检查** ⇒ **一笔 PTB 内混用** v1 估值 + v2 闪电贷 + v3 赎回；
     ③ `Sharehouse` 是**共享对象**，任何交易可 `&mut` 引用 ⇒ **跨版本混用无需特权角色**。
   - v1 记账看不见 v3 的动态字段 ⇒ `apply_accounting` 把 AUM 覆写成维持保证金 ⇒ AUM 塌缩 ⇒ 铸出虚高 LP 再从 v3 提。
2. **Halo2 未锚定底点**（The Far Orchard）—— 上游根因是 **CVE-2026-54496 / GHSA-ww9q-8r59-xv46（critical）**：
   - 定位 `halo2_gadgets/src/ecc/chip/mul/incomplete.rs`（约 L309-L310）：非完备点加阶段用 **`assign_advice()`** 喂底点坐标
     —— **只做 witness 赋值、不引入约束**；已有 `q_mul_2` 只强制**循环内各轮底点彼此相等**，
     **没有任何约束把它等于真正的底**。
   - 修复 = 首次迭代 `assign_advice()` → **`copy_advice()`**（copy 约束钉住首值 + `q_mul_2` 传递性覆盖全循环）。
     因修电路会改变被钉死的 verifying key ⇒ 网络层必须**硬分叉（NU6.2）**；影响 `halo2_gadgets <0.5.0` /
     `orchard <0.14.0` / `zcash_primitives <0.28.0` / `zebrad <5.0.0` / `zcashd <6.20.0`。
   - **代数伪造式**：对任意目标 `pk_target` 取随机非零 `sk_attacker`，令 **`B' = [sk_attacker⁻¹]·pk_target`**
     ⇒ 电路内 `[sk_attacker]·B' = pk_target` 恒成立。
     每片叶子换一个随机 `sk` ⇒ **每个 nullifier 都不同**（绕过 `nullifierUsed`）。
   - 挑战侧的信任边界：`FarOrchard` **不自己验 ZK 证明**，只验 EIP-712；所以"每叶一份新证明"是必需的。
   - 🔴 **无任何第三方公开 WP** —— 上面"为什么未锚定可被利用"来自 **CVE 公告原文**，不是挑战 WP，引用时要分清。
3. **预言机现货价 + 闪电贷**（Caldrin's Day Away）：判据是"被信任的调用其**返回值**可否被操纵"，
   与"调用是否被批准"无关 —— 这是审计里极易漏的一层。

**⚠️ flag 真实性（别编造）**：官方 README 公开了 Eldorion / HeliosDEX / EldoriaGate 三个；
公开 WP 给了 CA2023 Navigating the Unknown 与 CA2026 Caldrin's Day Away；
**Russian Roulette / Recovery / Second Stamp / The Far Orchard 的 flag 未公开**（README 写 `REDACTED` 或"仅实例返回"）；
**Lucky Faucet 已于 2026-09-29 实战取得：`HTB{<redacted>}`**（HTB Labs 实例与 CTF 期同值，可交叉验证）。

**🔴 三条跨题元模式（CA 系列反复出现，也适用于真实审计）**
1. **"检查通过了" ≠ "值是对的"** —— 检查可能做在**错误的位宽**上（EldoriaGate 用 256 位比较去抓 uint8 环绕）、
   批准的是**调用而非返回值**（Caldrin 的 stamped order）、或**只验签名不验证明**（The Far Orchard 的 `FarOrchard` 不验 ZK）。
   看到 `require(verify(...))` 先问：它到底约束了什么？
2. **同一笔交易的原子性是放大器** —— 同 `block.timestamp` 批量调用（Eldorion）、同笔多轮套利（HeliosDEX）、
   闪电贷抬价后立刻重估（Caldrin）、一条 PTB 内混用三个包版本（Second Stamp）。
   ⇒ 任何"每次调用/每个区块才生效一次"的防护，都要问**同笔交易内重复调用会怎样**。
3. **旧代码/旧版本不会自动失效** —— Second Stamp 的核心教训（升级后旧入口仍可调用同一共享对象）；
   同理 `private` 变量、已 retired 但仍可读的合约状态。

**⚠️ 不要混淆的两个"签名问题"**：526 / 1338 是 **ECDSA 可塑性**（同一签名的另一种合法编码绕过按字节串去重）；
The Far Orchard 的 `recover` 用的是 **EIP-712 + `_hashTypedDataV4` + `nullifierUsed`，写法是正确的**，
它的问题在"信任边界"（后端给签名，链上不验证明）—— 两者是不同层的缺陷。

### 4.13 `abi.encodePacked` 打包碰撞 —— 724 NotADemocraticElection（Easy, retired, Business CTF 2024 迁移）
> ✅ **2026-09-29 实战验证**：HTB Labs 容器实打实跑通（10 票 → `winner()=CIM`）并提交成功。

- **判据 `TARGET.winner() == bytes3("CIM")`**；Setup 已注册 ALF/CIM 两党，并以 **100 ether** 替
  `("Satoshi","Nakamoto")` 押注（`TARGET_VOTES = 1000e18`）。
- 合约漏洞：`vote()` 的权重取 `voters[getVoterSig(name, surname)].weight`，而
  `getVoterSig = abi.encodePacked(name, surname)` = **name 与 surname 的 UTF-8 首尾直接相接**；
  但唯一性/归属校验走的是 `uniqueVoters[name][surname]`（**二维 mapping，两个字段分开存**）。
- ⇒ **两个空间不重合**：`("Satosh","iNakamoto")`、`("SatoshiN","akamoto")` … 共 14 种切分在
  `uniqueVoters` 里彼此互异（每个都能单独 deposit 一次、各自通过 `== msg.sender` 校验），
  **但拼接后都是 `"SatoshiNakamoto"`** ⇒ 每一次 `vote` 都在借用 Satoshi 的 100 ether 权重。
- 100e18 × **10** = 1000e18 ⇒ 恰好触发 `checkWinner`，`winner = CIM`。
- 🔴 **必须跳过 `i=7`**（`("Satoshi","Nakamoto")` 正是 Setup 已占用的那一格，deposit 会
  `Already deposited` revert）；可用切分实际 13 个，够 10 票。
- 🔴 `winner()` 是 **bytes3**，初值 `0x000000`；`checkWinner` 已被 `vote()` 同笔调用，**不用单独调**。
- 🔴 这**不是密码学签名问题**（区别于 526/1338 的 ECDSA 可塑性）—— 是 Solidity **编码层歧义**：
  官方文档明确警告 `abi.encodePacked` 两个**动态类型相邻**时不可作为唯一标识。
  同类面一律要问"边界能不能挪"：`keccak256(abi.encodePacked(a,b))` 当签名摘要、`abi.encodePacked(user, amount)` 当订单 id。
- 参考值（该实例，⚠️ 每实例不同，用前从菜单端口 1 重取）：
  player `0xC39846cBd4011843A23318798304717961AdBB7e` · target `0xa138390898092218cff7fb5F7Fd0955f0A2F97a6` ·
  setup `0xf29640029C111c8Fe40Ba5090BC31f2bF57A4b79` · flag `HTB{<redacted>}`（CTF 期静态 flag）。
- 官方 solver：`hackthebox/business-ctf-2024` → `blockchain/NotADemocraticElection [Easy]/htb/solver.py`。

### 4.14 编译元数据 / NatSpec 泄露口令 —— 725 MetaVault（Easy, retired, Business CTF 2024 迁移）
> ✅ **2026-09-29 实战验证**：从链上 bytecode 抠出 CID `QmX9L9…fffkN` → 元数据里读到明文口令 → `emergency()` 一笔抽干 100 ETH。

- **判据 `address(TARGET).balance == 0`**；Setup 构造时 `TARGET.deposit{value: 100 ether}()`。
- 合约：硬编码 `bytes32 constant private VAULT_SECRET_K256`，`emergency(string _secret)` 比
  `keccak256(bytes(_secret))` 相等就 `selfdestruct(payable(msg.sender))`。源码注释写着
  *"plaintext secret: [REDACTED] / The secret will be stripped before open sourcing the code. **Comments are not compiled anyway.**"*
  —— **最后半句是错的**，这正是全题的洞。
- 🔴 **关键事实：NatSpec 注释会被编译进 CBOR 元数据并随 bytecode 永久上链**。取法（**不用装 solc、不用 Sourcify**）：

  ```python
  code   = eth_getCode(TARGET)                 # 运行时字节码
  length = int.from_bytes(code[-2:], 'big')    # 末尾 2 字节 = 元数据长度（大端）
  meta   = code[-length-2:-2]                  # CBOR 元数据
  # 固定结构: a2 64 "ipfs" 58 22 12 20 <32B sha256> 64 "solc" 43 <3B 版本>
  # CIDv0 = base58btc(0x12 0x20 + digest)      # 0x12=sha2-256, 0x20=32 字节
  ```
  本题 meta = `a264697066735822122082d2cd9b…874e7b64736f6c6343000819` ⇒
  **CID `QmX9L9Q9QkM3ytQ1Wk3jKAqNDXYhK8RFQHcfq8QXyfffkN`**、solc `0.8.25`。
- 该 CID 指向**元数据 JSON 本身**（不是源码）；JSON 里三个泄露面：
  ① **`output.devdoc.stateVariables.VAULT_SECRET_K256.details`** = *"plaintext secret: **<REDACTED>** …"* ← 答案就在这；
  ② `settings.compilationTarget` = 开发者本机路径 **`MoD_devs/src-secrets-embedded_DONOTDISCLOSE/MetaVault.sol`**；
  ③ `sources[...].urls` 里还有**源码**的 IPFS/BZZ 地址（本题 `QmeovAdT8rKA9skF4WWBr6M8PRXj14poYLjbb7gtcuNASs`）。
- 🔴 **IPFS 网关现状（2026-09 实测）**：`ipfs.io` **已死**（SSL 直接失败）、`cloudflare-ipfs.com` 同样不通；
  **`https://gateway.pinata.cloud/ipfs/<cid>` 可用**，但**Python `urllib` 直连它会 403**（UA/网关策略），换客户端或换网关即可。
  ⇒ **403 / SSL 失败 ≠ 内容不存在，先换网关再下结论**。
- 🔴 本机**不需要装 base58 库**：30 行纯 Python 即可实现 `base58btc`（Bitcoin 字母表 + 前导零→`1`）；
  脚本见工作区 `htb-metavault/meta.py`（CID 解码 + 网关轮询）。
- 🔴 **好习惯**：调 `emergency` 前先把 `Web3.keccak(text=SECRET)` 与链上常量比对（本题 `42c10591…` 完全一致），
  比直接赌一把稳 —— 口令来自二手文本时尤其值得校一次。
- 🔴 **`selfdestruct` 的 Cancun 语义在本题可再验一次**：抽干后 `eth_getCode` **仍有 1104 字节**（EIP-6780 不再删代码），
  但余额 0、`isSolved()==True` —— 与 §4.10 的注记同源：**判据只认余额**。
- 参考值（该实例）：player `0xc3265c0Bc50D9FE6aBBd4A1Bfc19aaeF9eB286cC`（余额 **5000 ETH**）·
  target `0x59482703bd774c5b80762BF6eE1d1adf91Dcb050` · setup `0x8F87BA59580DC1e82Ae72f76e92A69E97E01f73f` ·
  **flag `HTB{<redacted>}`（CTF 期静态 flag，Labs 实例同值）**。
- ⚠️ **推广**：任何"源码公开 + 编译时用默认 metadata"的合约都适用；判据是
  `settings.metadata.bytecodeHash`（`ipfs` / `bzzr1` / `none`）—— **`none` 才是真删干净**。
  "注释不会被编译"是**广泛存在的错误认知**，审计时见到硬编码 hash + 注释提及明文，第一件事就是拉元数据。

## 5. 工具链与环境（本机实测）

- **HTB 只给 RPC + 私钥，工具自带**。两条主流路线：
  - **Foundry**：`cast call/send` 手搓、`forge create` 部署攻击合约（本卡多数题的步子都可用它表达）。
  - **Hardhat / ethers.js**：写脚本 + `deploy`，适合需要复杂状态机的题（502）。
  - **web3.py + py-solc-x**：适合把 527 那类"构造多参 bytes[] 调用"脚本化。
- 🔴 **本机现状（2026-09-29 更新）**：`cast/forge/anvil/foundryup` **仍然没有**；但 python 侧**已经装好
  `web3 8.0.0` + `eth-account`**（装进 DSH bundled python 即可，一条命令
  `<bundledPython>\python.exe -m pip install web3 eth-account`，实测约 1 分钟、无编译依赖）
  ⇒ **首选路线改为 web3.py**，不再需要 WSL/foundry。备选仍是 `node/npm`（`npm i hardhat ethers`）与 WSL Ubuntu。
- 🔴 **能不解签名就别解**：HTB **Labs 容器**的 anvil 实例里玩家账户是**解锁的**（`eth_accounts` 直接包含它），
  可以直接 `w3.eth.send_transaction({"from": PLAYER, ...})`；只有 **CTF 附件型**实例（自建 RPC、账户未解锁）
  才需要菜单给的那把私钥去签名。开局先 `eth_accounts` 一眼，能省掉整段签名代码。
- **Foundry 版本坑**：新版 cast 对该挑战 RPC 会发 `input` 字段 → `-32602 unknown field 'input', expected one of 'from','to',...`，
  或 `intrinsic gas too high`。两条绕法：`foundryup -C cc5637a`（退到旧 build）或给 `cast send`
  补 `--value 0 --gas-limit 1000000 --gas-price 20000000000`。

## 6. 坑清单（跨题高频）

1. **先读 `isSolved`，不要先读故事** —— 题面叙事（"巨龙/传送门/魔法金库"）与漏洞无关。
2. **`isSolved` 的语义常"还差一步"**：502 的 `unlock()` 不算通关（要 `claimContent()`）；506 的 `claimPrize()`
   把资产给**攻击合约**（要再 `keyTransfer`）；504 要成为 **index 2** 那件物品的 owner。
3. **环境相关值一律现算**：合约地址、`timeout` 初值、`nonce`、需要回绕的次数 —— WP 里给的都是**单实例值**。
4. **攻击者常常必须是合约**（501 要 `tx.origin != msg.sender`；506 要能收回调 + 需新地址躲 `blacklisted[tx.origin]`）。
5. **公开脚本未必能跑**：流传的 GitHub 解法里有逻辑错（Distract and Destroy 少了"EOA 先占 aggro"这一步）和
   漏最后一步（Magic Vault 缺 `claimContent()`）的 —— 抄之前先对着源码核一遍。
6. **`require` 写在循环里 = 没有 require**（527）；写完立刻对照"调用者能不能让循环 0 次"。
7. **看 `pragma` 再决定要不要找溢出**：0.8+ 上死找下溢是纯浪费时间（500 传 `max` 会 revert）。
8. **同名函数两条路径的校验常不一致**（504：`_transfer` 恒真、`_transferFrom` 正确）—— 逐条读，别假设对称。
9. `verify`/`ecrecover` 类校验：**"签名字节"不是身份**（可塑性），只有 `(signer, digest/nonce)` 才是。
10. **`abi.encodePacked` 当唯一标识 = 边界可挪**（724）：唯一性校验与取值用的是**两套不同的键**时，
    先分别画出"校验空间"与"取值空间"，两空间不等价的地方就是洞。
11. **别手打 token，别拿 labs API 当枚举工具**：JWT 988 字符错一个即 401；`x-ratelimit-limit: 15` 几次就 429。
    把 API 调用放进浏览器上下文最稳。
12. **HTB Labs 容器有两个端口**：一个是 RPC（根路径即 RPC），一个是**菜单式 TCP 服务**（`1/2/3`）。
    `Invoke-WebRequest` 报"协议冲突"、`curl` 报 `HTTP/0.9 when not allowed` 的那个就是菜单端口；
    `GET /flag` 是 401，flag 只能从菜单端口取。
13. **端口数不固定，且可能有 Web 前端**（725 有 3 个：RPC / 菜单 / **HTML 页面**）。
    Web 那页常常就是**出题人给的提示**（725 写着 "Don't Trust, Verify" + "compiled with metadata, published on IPFS"）
    —— 开局把每个端口都看一眼，比闷头读源码更快。
14. **"注释不会被编译"是错的**：NatSpec 会进 CBOR 元数据并上链（725）。见到硬编码 hash + 注释提"明文口令"，
    **第一件事是 `eth_getCode` 抠元数据**，不是去爆破。
15. **一个账号的容器不能并存**：开新题会顶掉旧题（同 IP、整批换端口）。别拿旧端口继续打，也别假设能同时开两道。
16. **IPFS 网关会失效**（`ipfs.io` 2026-09 已死）：能返回 403 说明**网关活着但拒绝你**，换 `gateway.pinata.cloud`
    或换 HTTP 客户端即可 —— **别把"取不到"当成"不存在"**。
17. 🔴 **取到 flag 后实例会被重新部署（684 实测）**：点完菜单 `3 - Get flag` 再回读链，
    `eth_blockNumber` 回到 **1**、旧 target/setup 的 `eth_getCode` 变空、`eth_accounts` 换成两个全新地址，
    菜单 `1` 也给出**全新的 private key / address / target / setup**。
    ⇒ **"打完再回读状态复现"这套做法不成立**；要做状态取证（例如读 Setup 存储反推 `isSolved()` 判据）
    **必须在取 flag 之前完成**。
18. **题目 README/题面的判据描述 ≠ 链上实现的判据**（Lucky Faucet）：README 说"需要 ≥10 ETH"，
    但玩家开箱就有 5000 ETH 且 `isSolved()` 为 False ⇒ 真判据是**增量**。
    **永远以链上 `isSolved()` 为准**，别照题面文字推判据。

## 7. 与相邻卡分工

| 卡 | 分工 |
|---|---|
| `challenge-crypto-prng` | PRNG 线性预测/协议缺陷（**不是**链上可预测性；502 属本卡） |
| `weak-prng-predictable-seed` | `srand/time(NULL)` 类时间种子（502 的 `blockhash` 派生属本卡） |
| `crypto-classic-attack-patterns` | 填充预言机/长度扩展/ECB 等经典密码误用；**ECDSA 可塑性（526/1338）只在本卡** |
| `challenge-web-chain` | 多级 Web 链（HTTP/浏览器层，不碰链上状态） |
| `challenge-insane-playbook` | 挑战总路由；本卡是它的 blockchain 分册 |
| `weak-rsa-key-recovery` | 弱 RSA；PQ 侧（WOTS/XMSS）只在本卡 |
