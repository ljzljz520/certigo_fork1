# certigo 多证书容器解析完整性语义修正 — 实施计划

## Repository Research

### 当前链路

- 公开读取 API（[lib/certs.go](file:///Users/kkcarrot/swe-project/certigo_fork1/lib/certs.go)）：`ReadAsPEMFromFiles` / `ReadAsPEM` / `ReadAsX509FromFiles` / `ReadAsX509`，均为「逐输入 → `readCertsFromStream` → 回调」模型；回调签名 `func(*pem.Block, string) error` 与 `func(*x509.Certificate, string, error) error`。
- `readCertsFromStream` 按格式（PEM/DER/PKCS12/JCEKS）产出 PEM block；X509 侧经 `pemToX509` 适配；verify/dump/caBundle 均在 [cli/cli.go](file:///Users/kkcarrot/swe-project/certigo_fork1/cli/cli.go) 与 [lib/verify.go](file:///Users/kkcarrot/swe-project/certigo_fork1/lib/verify.go) 消费。
- `connect` 的证书来自 TLS 连接状态，不走文件解析链路，本次不改动其取证书逻辑。

### 已确认缺陷（本地复现）

1. **PEM 扫描无完成校验**（certs.go:202-212, 433-446）：`for scanner.Scan()` 结束后直接 `return nil`：
   - 不检查 `scanner.Err()`：block 超过 bufio.Scanner 默认 64KiB token 上限时静默截断为成功；
   - EOF 处未闭合的 `-----BEGIN ...` 块、无法解码的尾部数据被当作「允许的说明文字」丢弃。
   - 复现：2 张合法证书后追加截断块 → dump JSON 仅报 2 张且退出 0；verify 继续在截断链上做信任判断（实测退出码 1，报的是证书过期而非解析失败）。
2. **PKCS7 只展开第一张**（certs.go:177-185）：`for _, cert := range certs { return callback(...) }` 首次回调即 return。实测 DER 与 PEM 两种形式、单 envelope 内含 2 张证书均只输出 1 张。
3. **DER 宽松消费**：`pkcs7.ParseSignedData` 允许前缀解析后残留字节；X.509/PKCS7 双解析试探下，尾部垃圾无显式完整性结论。
4. **无来源/位置信息**：回调只有 format 字符串；多文件、多块、容器内位置无从诊断；无资源上限（块数、容器展开数、字节数）。
5. **失败契约分裂**：dump 解析错误走 stderr、退出 2，但机器可读输出里没有失败与来源；`--first` 在 PEM 路径靠回调跳过（扫描仍继续），text/json 路径事后切片；截断类失败不被感知，因此无法保证「展示选择不掩盖解析失败」。

### 兼容性约束

- `test-certs/*.p7b` 实际为 **PEM 形式** PKCS7（`-----BEGIN PKCS7-----`）；keystore 口令固定 `password`（[test-certs/Makefile](file:///Users/kkcarrot/swe-project/certigo_fork1/test-certs/Makefile)）。
- cram 黄金测试中 4 个 JSON 用例（dump-leaf / small-key / spiffe / first-only-to-json）逐字符比对 JSON；dump --pem 系列逐字节比对 PEM（含 pkcs12/jceks 的 block 顺序与 friendlyName header）。
- `go.mod` 要求 go 1.26（本机 1.27）；新文件必须带 goheader 许可证头；lint 启用 errcheck/govet/staticcheck/ineffassign/unused。
- `pemToX509` 对 CERTIFICATE REQUEST 向 stdout 打印 warning 的现有行为保留。

## 设计：统一的内部解析契约

### 新增类型（lib 包导出，供 cli 消费；旧 API 作为兼容适配器保留）

```go
type Source struct {
    Name     string `json:"name,omitempty"`      // 文件名；stdin/无名流为 ""
    Format   string `json:"format"`              // PEM / DER / PKCS12 / JCEKS
    Block    int    `json:"block"`               // 该输入内 PEM/合成 block 的 1-based 序号
    Envelope int    `json:"envelope,omitempty"`  // PKCS7 envelope 1-based 序号（DER 可拼接多 envelope）
    Index    int    `json:"index,omitempty"`     // envelope 内证书 1-based 位置；普通 CERTIFICATE 块为 0
    Offset   int64  `json:"offset,omitempty"`    // block 在输入流中的字节偏移（PEM）
}

type Diagnostic struct {
    Kind    string  `json:"kind"`    // skipped_block / malformed_block / resource_limit / read_error / unknown_format / callback_terminated
    Message string  `json:"message"`
    Type    string  `json:"block_type,omitempty"` // skipped/malformed 时的 PEM block 类型
    Source  Source  `json:"source"`
}

type CertPosition struct { // parse_result.inputs[].certificates 元素，按回调顺序
    Block, Envelope, Index int
    Offset                 int64
}

type InputParseResult struct {
    Name         string          `json:"name,omitempty"`
    Format       string          `json:"format"`
    Status       string          `json:"status"` // complete | incomplete | terminated
    Certificates []CertPosition  `json:"certificates"`
    Diagnostics  []Diagnostic    `json:"diagnostics,omitempty"`
}

type ParseResult struct{ Inputs []InputParseResult }
func (r *ParseResult) Complete() bool // 所有输入 status=complete 且无 error 级 diagnostic
func (r *ParseResult) Error() error   // 聚合 message（旧适配器用）

var ErrCallbackTerminated = errors.New(...) // errors.Is 可判定调用方主动终止
```

- 非致命：块外说明文字（prose，允许、不进 JSON）、X509 读取器跳过的非证书块（`skipped_block`，如私钥/CSR）。
- 致命（输入 incomplete）：`malformed_block`（未闭合块、pem 解码失败、X509/PKCS7 解析失败、DER 尾部残留）、`resource_limit`、`read_error`、`unknown_format`。
- 调用方回调返回错误：该输入 `terminated`，整体立即停止，Read 函数返回可用 `errors.Is(err, ErrCallbackTerminated)` 判别的错误；与格式错误明确区分。

### 新读取入口（新增，不替换旧签名）

```go
type Input struct{ Name string; Reader io.Reader }
type X509SourceFunc func(*x509.Certificate, Source, error) error
type PEMSourceFunc  func(*pem.Block, Source) error

func ReadX509Inputs(inputs []Input, format string, password func(string) string, cb X509SourceFunc) (*ParseResult, error)
func ReadPEMInputs (inputs []Input, format string, password func(string) string, cb PEMSourceFunc)  (*ParseResult, error)
```

- 解析类问题不返回 Go error，全部进 `ParseResult`；返回 error 仅用于回调终止。
- 旧 4 个公开函数改为薄适配器：内部调用新入口，签名、错误聚合方式、format 猜测失败立即返回的旧行为保持；`pemToX509` 修正为遍历 PKCS7 全部证书，且仍按旧契约对解析失败调用 `callback(nil, format, err)`。

### 统一展开契约（PEM / DER / PKCS7 / keystore）

- 每个格式产出统一的「带 Source 的 block 流」：
  - PEM：每个 `pem.Decode` 块，Block 递增，Offset 为块起始字节；
  - DER-X509：每张合成 CERTIFICATE block；DER-PKCS7：每个 envelope 一个 PKCS7 block（Envelope=Block）；
  - PKCS12/JCEKS：每个现存导出 block（保留 alias header 与顺序），Block 递增。
- X509 适配层统一展开：CERTIFICATE → 解析回调；**PKCS7 → 严格解析所有 envelope，每张证书都回调**，Source 带 Envelope/Index；解析失败按位置记 `malformed_block` 并继续（不中止整个输入）；其他类型 → `skipped_block`；CSR 保留 stdout warning。
- PEM 适配层逐块透传（dump --pem 仍输出 PKCS7 原文与私钥块，行为不变）。

### PEM 扫描器重写（不是只加大缓冲区）

保留 bufio.Scanner（流式），自定义 SplitFunc + 闭包状态：
- 初始缓冲 64KiB、上限 `maxPEMBlockBytes = 1 MiB`（可验证上限）；`ErrTooLong` → `resource_limit` + incomplete，绝不当成功；
- 跟踪累计字节偏移；块前文字（s_client CONNECT 输出等）允许并跳过；
- 数据以 `-----BEGIN ` 开头但 EOF 仍无完整块 → sentinel `errUnclosedPEM` → `malformed_block`（含截断块起始 Offset、Block 序号）+ incomplete；
- 有 END 行但 pem.Decode 失败（坏 header/base64）→ 跳过该坏块、记 `malformed_block`、继续后续块；
- 无 BEGIN 的尾部在 EOF 作为 prose 消费（complete）；非 EOF 保留至多 11 字节后缀防止标记跨读边界。
- 块数上限 `maxBlocksPerInput = 100000`；PKCS7 展开证书数上限 `maxContainerCerts = 100000`；DER/PKCS12/JCEKS 全量读取包 `maxContainerBytes = 100 MiB` 的 limitReader。上限做成包级变量，包内测试可临时调低以低成本验证。

### pkcs7 包

新增 `ParseSignedDataStrict(data []byte) ([]*SignedDataEnvelope, error)`：循环解析并要求字节全部消费、至少 1 个 envelope，否则 error；`ParseSignedData`/`ExtractCertificates` 保留供兼容。

## Files and Modules

- [lib/certs.go](file:///Users/kkcarrot/swe-project/certigo_fork1/lib/certs.go)：新增类型/入口/扫描器/限制/统一展开；旧 4 个公开函数与 `pemToX509` 改适配器并修复 PKCS7 循环；keystore 路径加限制与 Source。
- [pkcs7/pkcs7.go](file:///Users/kkcarrot/swe-project/certigo_fork1/pkcs7/pkcs7.go)：新增 `ParseSignedDataStrict`。
- [lib/verify.go](file:///Users/kkcarrot/swe-project/certigo_fork1/lib/verify.go)：`SimpleResult` 增加 `ParseResult`（JSON key `parse_result`，MarshalJSON 输出）；`caBundle` 改用严格读取，解析不完整直接返回 error（不进入信任判断）；新增导出 `LoadRoots(caPath)` 与 `VerifyChainWithRoots(...)`，`VerifyChain` 保留为 wrapper（connect 继续使用）。
- [cli/cli.go](file:///Users/kkcarrot/swe-project/certigo_fork1/cli/cli.go)：
  - dump 改用新入口；JSON 始终携带 `parse_result`；先输出（含部分结果的）单个 JSON 对象，再按完整性决定退出码（不完整 → 2）；text 模式保持现有输出，错误走 stderr；`--first` 仅在展示层切片，parse_result 反映全部输入，失败仍退出非零；
  - verify：链输入与 CA 都完整解析后才调用 `VerifyChainWithRoots`；解析失败退出 2，`--json` 时 stdout 输出单个 `{"error":..., "parse_result":...}`；信任失败退出 1 不变；
  - connect 不改。
- `lib/certs_test.go`（新建）、`cli/cli_test.go`（扩充）、可能新增 1 个 cram 端到端用例；4 个 JSON 黄金 cram 预期更新（新增 `parse_result` 字段，用实际二进制输出校准）。
- 测试夹具：用 openssl 生成「单 envelope 多证书」的 DER/PEM p7b，放入 `lib/testdata/`；>64KiB 合法证书在测试内用 `x509.CreateCertificate` + 大 Extension 动态生成；keystore 复用 `test-certs/*.p12/*.jceks`。

## Implementation Steps

1. pkcs7：加 `ParseSignedDataStrict` 与小测试（多 envelope 拼接、尾部残留、空输入）。
2. lib：定义 Source/Diagnostic/ParseResult/Input、限制变量、sentinel 错误；实现 PEM 严格扫描器（偏移/未闭合/坏块/prose/资源上限）。
3. lib：重构 `readCertsFromStream` 为 block 流 + 两个适配层（PEM 透传 / X509 全量展开 PKCS7、逐张回调、位置透传）；DER 严格全消费；keystore 加限制；实现两个 `Read*Inputs`；旧 4 个公开函数改为适配器并修复 `pemToX509`。
4. lib/verify.go：caBundle 严格化；`SimpleResult.ParseResult` 序列化；`LoadRoots` / `VerifyChainWithRoots`。
5. cli：dump（含 --first/--pem/--json/退出码）、verify（门控、失败 JSON 单对象）接线。
6. 测试：lib 单测（下方场景全量）、cli 测试（退出码/单 JSON 对象/来源/--first 不掩盖失败）、更新 4 个 cram 黄金 JSON、新增 1 个 cram shell 断言用例（CI 跑，本地无 cram 则用 Go 测试覆盖）。
7. 全量验证并修正。

## 验证场景（测试断言点）

- 多证书 PEM：证书数、Block 序号、status=complete；
- 单 envelope 含多证书的 DER-PKCS7 与 PEM-PKCS7：证书数=2，Envelope/Index 正确（回归当前只出 1 张）；
- 多文件混合输入（PEM + DER p7b）：全局顺序、Source.Name/Block 正确；
- 超过 Scanner 默认 64KiB 但低于上限的合法 PEM：完整解析成功；
- 合法证书后的截断块：部分证书保留 + malformed_block 诊断（含来源位置）+ incomplete；dump JSON 为**单个可解析对象**、退出 2；verify 退出 2 且不产出信任结论；
- 回调主动报错：errors.Is(ErrCallbackTerminated)、status=terminated、此前证书已交付；
- 资源上限：调低阈值后超限输入报 resource_limit + incomplete + 退出 2；
- `--first`：仅展示 1 张，但后续输入解析失败仍反映在 parse_result 且退出非零；
- 兼容性：现有 p12/jceks PEM 导出（顺序、私钥块、header）、PEM 说明文字、CSR warning、空输入 warning 退出 0、connect 行为不变。

## Dependencies and Considerations

- 所有新 API 为**增量添加**，旧公开函数签名与既有错误文本风格保留；`connect` 不经文件解析，风险隔离。
- JSON 仅增量加 `parse_result`，证书对象本身不变；需更新 4 个逐字符黄金用例，属预期内的有意变更。
- dump 文本模式与 --pem 输出格式不变；失败时 JSON 只打印一次（单次 marshal），stderr 仅为辅助人类信息。
- 资源上限常量取宽松但确定的值（1MiB block / 100k 块 / 100k 容器证书 / 100MiB 容器），包内测试通过覆盖变量验证触发，避免测试生成海量数据。
- jceks.LoadFromReader 内部自读，用 limitReader 包裹其 reader。

## Validation

- `go build ./...`、`go vet ./...`、`go test -v ./...`（含新测试全绿）；
- 若本地有 golangci-lint 则运行，否则以 go vet/staticcheck 自测为准；
- 手动运行 cram 等价命令（本地无 cram：直接跑二进制 + python3 json 校验）核对 dump/verify/--first/--pem/keystore 场景；
- 对照现有 cram 用例逐个手工跑一遍受影响命令（pkcs12/jceks/mozilla bundle/first-only）。

## Risks

- **黄金 cram 用例失败**：用二进制实际输出精确更新 4 个 JSON 预期，不手改；其余文本/PEM 用例预期零 diff。
- **严格化误伤合法输入**（如 openssl 输出尾部、PEM p7b 换行差异）：prose 规则与现状 pem.Decode 一致；DER 以「全消费」为准并用现有全部 test-certs 夹具回归。
- **pkcs12 deprecated API 顺序**：不改转换逻辑，仅在外层包位置/限制，靠现有 dump-pkcs12-*.t 与新增 Go 测试守住。
- **旧 API 使用方依赖「部分结果即成功」**：旧适配器现在会对 incomplete 返回聚合 error——这正是修复语义；回调流契约（逐张调用、格式字符串、parse 错误回调）保持不变。
