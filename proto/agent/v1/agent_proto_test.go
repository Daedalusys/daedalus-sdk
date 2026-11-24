package agentv1_test

import (
	"testing"

	agentv1 "github.com/Daedalusys/daedalus-sdk/proto/agent/v1"
	"google.golang.org/protobuf/proto"
)

// AgentService 的线上方法表必须暴露只读工具调用面。守护的是 proto 契约本身:
// service 块里的 RPC 一旦被误删,控制面编译期能过但运行期才发现。
func TestAgentService_ExposesReadOnlyToolRPCs(t *testing.T) {
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
func TestCallToolResponse_ToolErrorIsDistinguishable(t *testing.T) {
	ok := &agentv1.CallToolResponse{IsError: false, ContentJson: "{}"}
	bad := &agentv1.CallToolResponse{IsError: true, ErrorMessage: "路径越界"}
	if ok.GetIsError() || !bad.GetIsError() {
		t.Errorf("is_error 语义丢失: ok=%v bad=%v", ok.GetIsError(), bad.GetIsError())
	}
}
