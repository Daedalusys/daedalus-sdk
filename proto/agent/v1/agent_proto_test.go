// agent_proto_test.go 守护 agent.v1 的线上契约:RPC 方法表与消息的 wire 往返。
// 一律走真 marshal/unmarshal;往返只证明收发自洽,字段号/tag 需单独钉。
// 协议只承载传输,是否放行由节点侧判定;对端实现见 daedalus-agent 仓与 AGENTS.md。
package agentv1_test

import (
	"testing"

	agentv1 "github.com/Daedalusys/daedalus-sdk/proto/agent/v1"
	"google.golang.org/protobuf/proto"
)

// AgentService 的线上方法表必须暴露工具调用面。守护的是 proto 契约本身:
// service 块里的 RPC 一旦被误删,控制面编译期能过但运行期才发现。
func TestAgentService_ExposesToolRPCs(t *testing.T) {
	got := map[string]bool{}
	for _, m := range agentv1.AgentService_ServiceDesc.Methods {
		got[m.MethodName] = true
	}
	for _, want := range []string{"ListTools", "CallTool"} {
		if !got[want] {
			t.Errorf("AgentService 缺少 RPC %s", want)
		}
	}
}

// 入参 JSON 原样搬运,不做结构解析;往返后必须逐字节一致。
func TestCallToolRequest_RoundTrip(t *testing.T) {
	in := &agentv1.CallToolRequest{PluginId: "daedalus.shell", ToolName: "shell_exec", ArgumentsJson: `{"command":"df"}`}
	b, err := proto.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := &agentv1.CallToolRequest{}
	if err := proto.Unmarshal(b, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.GetPluginId() != "daedalus.shell" || out.GetToolName() != "shell_exec" || out.GetArgumentsJson() != `{"command":"df"}` {
		t.Errorf("往返后字段不一致: %+v", out)
	}
}

// 插件自报的业务错误(is_error=true)与正常结果在反序列化后必须仍可区分。
// 必须过 wire:字段号或 tag 写错时,读回刚赋进去的 Go 字段会假绿。
func TestCallToolResponse_ToolErrorIsDistinguishable(t *testing.T) {
	roundTrip := func(t *testing.T, in *agentv1.CallToolResponse) *agentv1.CallToolResponse {
		t.Helper()
		b, err := proto.Marshal(in)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		out := &agentv1.CallToolResponse{}
		if err := proto.Unmarshal(b, out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return out
	}

	ok := roundTrip(t, &agentv1.CallToolResponse{ContentJson: "{}"})
	if ok.GetIsError() || ok.GetContentJson() != "{}" {
		t.Errorf("正常结果往返后失真: %+v", ok)
	}
	bad := roundTrip(t, &agentv1.CallToolResponse{IsError: true, ErrorMessage: "路径越界"})
	if !bad.GetIsError() || bad.GetErrorMessage() != "路径越界" {
		t.Errorf("插件业务错误往返后失真: %+v", bad)
	}
	// 往返是自洽的:改字段号不会让往返失败,所以线上号必须单独钉。
	// 控制面与 agent 分别升级时,is_error 从 1 挪走就是静默的语义翻转。
	if fd := bad.ProtoReflect().Descriptor().Fields().ByName("is_error"); fd == nil || fd.Number() != 1 {
		t.Errorf("is_error 的线上字段号不是 1: %v", fd)
	}
}

// ListToolsResponse 是唯一带嵌套 repeated 消息的响应;嵌套类型索引错位会让
// marshal 通过、解出来却是空列表或别的类型,只靠包 init panic 兜不住。
func TestListToolsResponse_NestedRoundTrip(t *testing.T) {
	in := &agentv1.ListToolsResponse{
		Tools: []*agentv1.ToolDescriptor{
			{
				PluginId:        "daedalus.shell",
				ToolName:        "shell_exec",
				Description:     "执行白名单内的 shell 命令",
				InputSchemaJson: `{"type":"object"}`,
				ReadOnly:        true,
			},
			{PluginId: "daedalus.fs", ToolName: "read_file"},
		},
		AuditSeq: 42,
	}
	b, err := proto.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := &agentv1.ListToolsResponse{}
	if err := proto.Unmarshal(b, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.GetTools()) != 2 {
		t.Fatalf("tools 数量=%d,期望 2", len(out.GetTools()))
	}
	first, second := out.GetTools()[0], out.GetTools()[1]
	if first.GetPluginId() != "daedalus.shell" || first.GetToolName() != "shell_exec" ||
		first.GetDescription() != "执行白名单内的 shell 命令" ||
		first.GetInputSchemaJson() != `{"type":"object"}` || !first.GetReadOnly() {
		t.Errorf("第 0 条工具往返后失真: %+v", first)
	}
	// 顺序也是契约:控制面按下标对齐节点清单,错位等于张冠李戴。
	if second.GetPluginId() != "daedalus.fs" || second.GetToolName() != "read_file" || second.GetReadOnly() {
		t.Errorf("第 1 条工具顺序或字段错位: %+v", second)
	}
	if out.GetAuditSeq() != 42 {
		t.Errorf("audit_seq=%d,期望 42", out.GetAuditSeq())
	}
}
