# known-gap：本层结构上检测不到的用例

放这里的报文**不是"规则写漏了"**，而是在当前的实现层不可能检测 —— 把它们混在
`positive/` 里会造成"验收通过"或"永远失败"的假象，所以单独放。

## protocol-cl-te.http —— Content-Length 与 Transfer-Encoding 并存（CL.TE 走私）

* 事实：Go 的 `net/http` 解析阶段就把 `Transfer-Encoding` 从 `r.Header` 移走
  （放进 `r.TransferEncoding`），chunked 时**连 `Content-Length` 一起删掉**。
  证据钉在 `internal/parser/headers_test.go`。
* 后果：任何在 `REQUEST_HEADERS` 上匹配这两个头的规则**永远不会命中**。
* 风险：不可观测 ≠ 可被利用。Go 服务器与反向代理会按解析后的语义重新编码请求
  再发给上游，CL/TE 歧义不会传到后端 —— 这一层是把歧义**归一化掉**，
  而不是把它**检测出来**。
* 真正的检测需要在 `net/http` 之前拦截原始字节，属于未实现能力（见 docs/DESIGN.md §8）。
* 仍需警惕的部署形态：donothack 前面还有一层会自己解释 CL/TE 的代理时，
  走私可能发生在"前端代理 ↔ donothack"之间。那是拓扑问题，应在部署文档里写明。
