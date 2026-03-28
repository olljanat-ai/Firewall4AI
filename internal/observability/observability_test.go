package observability

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

func TestDetectLLMEndpoint(t *testing.T) {
	endpoints := DefaultEndpoints()

	tests := []struct {
		host  string
		path  string
		found bool
		prov  Provider
	}{
		{"api.openai.com", "/v1/chat/completions", true, ProviderOpenAI},
		{"api.anthropic.com", "/v1/messages", true, ProviderAnthropic},
		{"generativelanguage.googleapis.com", "/v1beta/models/gemini-pro:generateContent", true, ProviderGemini},
		{"api.mistral.ai", "/v1/chat/completions", true, ProviderMistral},
		{"example.com", "/api/test", false, ""},
		{"api.openai.com", "/other/path", false, ""},
	}

	for _, tt := range tests {
		ep, ok := DetectLLMEndpoint(tt.host, tt.path, endpoints)
		if ok != tt.found {
			t.Errorf("DetectLLMEndpoint(%q, %q) found=%v, want %v", tt.host, tt.path, ok, tt.found)
		}
		if ok && ep.Provider != tt.prov {
			t.Errorf("DetectLLMEndpoint(%q, %q) provider=%v, want %v", tt.host, tt.path, ep.Provider, tt.prov)
		}
	}
}

func TestParseOpenAIRequest(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "Hello!"}
		]
	}`
	model, msgs := ParseLLMRequest(ProviderOpenAI, body)
	if model != "gpt-4o" {
		t.Errorf("model = %q, want %q", model, "gpt-4o")
	}
	if len(msgs) != 2 {
		t.Fatalf("len(msgs) = %d, want 2", len(msgs))
	}
	if msgs[0].Role != "system" || msgs[0].Content != "You are a helpful assistant." {
		t.Errorf("msgs[0] = %+v, unexpected", msgs[0])
	}
	if msgs[1].Role != "user" || msgs[1].Content != "Hello!" {
		t.Errorf("msgs[1] = %+v, unexpected", msgs[1])
	}
}

func TestParseOpenAIResponse(t *testing.T) {
	body := `{
		"choices": [
			{
				"message": {"role": "assistant", "content": "Hi there!"},
				"finish_reason": "stop"
			}
		],
		"usage": {
			"prompt_tokens": 10,
			"completion_tokens": 5,
			"total_tokens": 15
		}
	}`
	output, inTok, outTok, totalTok, reason := ParseLLMResponse(ProviderOpenAI, body)
	if output != "Hi there!" {
		t.Errorf("output = %q, want %q", output, "Hi there!")
	}
	if inTok != 10 || outTok != 5 || totalTok != 15 {
		t.Errorf("tokens = %d/%d/%d, want 10/5/15", inTok, outTok, totalTok)
	}
	if reason != "stop" {
		t.Errorf("finish_reason = %q, want %q", reason, "stop")
	}
}

func TestParseAnthropicRequest(t *testing.T) {
	body := `{
		"model": "claude-sonnet-4-20250514",
		"system": "You are a helpful assistant.",
		"messages": [
			{"role": "user", "content": "Hello!"}
		]
	}`
	model, msgs := ParseLLMRequest(ProviderAnthropic, body)
	if model != "claude-sonnet-4-20250514" {
		t.Errorf("model = %q, want %q", model, "claude-sonnet-4-20250514")
	}
	if len(msgs) != 2 {
		t.Fatalf("len(msgs) = %d, want 2", len(msgs))
	}
	if msgs[0].Role != "system" || msgs[0].Content != "You are a helpful assistant." {
		t.Errorf("msgs[0] = %+v, unexpected", msgs[0])
	}
}

func TestParseAnthropicResponse(t *testing.T) {
	body := `{
		"content": [
			{"type": "text", "text": "Hello! How can I help?"}
		],
		"stop_reason": "end_turn",
		"usage": {
			"input_tokens": 20,
			"output_tokens": 8
		}
	}`
	output, inTok, outTok, totalTok, reason := ParseLLMResponse(ProviderAnthropic, body)
	if output != "Hello! How can I help?" {
		t.Errorf("output = %q, want %q", output, "Hello! How can I help?")
	}
	if inTok != 20 || outTok != 8 || totalTok != 28 {
		t.Errorf("tokens = %d/%d/%d, want 20/8/28", inTok, outTok, totalTok)
	}
	if reason != "end_turn" {
		t.Errorf("stop_reason = %q, want %q", reason, "end_turn")
	}
}

func TestParseGeminiRequest(t *testing.T) {
	body := `{
		"contents": [
			{
				"role": "user",
				"parts": [{"text": "What is Go?"}]
			}
		]
	}`
	model, msgs := ParseLLMRequest(ProviderGemini, body)
	if model != "" {
		t.Errorf("model = %q, want empty (model is in URL)", model)
	}
	if len(msgs) != 1 {
		t.Fatalf("len(msgs) = %d, want 1", len(msgs))
	}
	if msgs[0].Content != "What is Go?" {
		t.Errorf("content = %q, want %q", msgs[0].Content, "What is Go?")
	}
}

func TestParseGeminiResponse(t *testing.T) {
	body := `{
		"candidates": [
			{
				"content": {
					"parts": [{"text": "Go is a programming language."}]
				},
				"finishReason": "STOP"
			}
		],
		"usageMetadata": {
			"promptTokenCount": 5,
			"candidatesTokenCount": 10,
			"totalTokenCount": 15
		}
	}`
	output, inTok, outTok, totalTok, reason := ParseLLMResponse(ProviderGemini, body)
	if output != "Go is a programming language." {
		t.Errorf("output = %q", output)
	}
	if inTok != 5 || outTok != 10 || totalTok != 15 {
		t.Errorf("tokens = %d/%d/%d, want 5/10/15", inTok, outTok, totalTok)
	}
	if reason != "STOP" {
		t.Errorf("finish_reason = %q, want %q", reason, "STOP")
	}
}

func TestExtractGeminiModel(t *testing.T) {
	tests := []struct {
		path  string
		model string
	}{
		{"/v1beta/models/gemini-pro:generateContent", "gemini-pro"},
		{"/v1/models/gemini-1.5-flash:generateContent", "gemini-1.5-flash"},
		{"/v1/models/gemini-pro", "gemini-pro"},
		{"/other/path", ""},
	}
	for _, tt := range tests {
		got := extractGeminiModel(tt.path)
		if got != tt.model {
			t.Errorf("extractGeminiModel(%q) = %q, want %q", tt.path, got, tt.model)
		}
	}
}

func TestParseInvalidJSON(t *testing.T) {
	model, msgs := ParseLLMRequest(ProviderOpenAI, "not json")
	if model != "" || msgs != nil {
		t.Errorf("expected empty result for invalid JSON, got model=%q msgs=%v", model, msgs)
	}

	output, in, out, total, reason := ParseLLMResponse(ProviderOpenAI, "not json")
	if output != "" || in != 0 || out != 0 || total != 0 || reason != "" {
		t.Error("expected zero values for invalid JSON response")
	}
}

func TestParseUnknownProvider(t *testing.T) {
	model, msgs := ParseLLMRequest(ProviderUnknown, `{"model": "test"}`)
	if model != "" || msgs != nil {
		t.Error("expected empty result for unknown provider")
	}
}

func TestContentToString(t *testing.T) {
	// String content.
	if s := contentToString("hello"); s != "hello" {
		t.Errorf("string: got %q", s)
	}
	// Array of text blocks.
	arr := []any{
		map[string]any{"type": "text", "text": "part1"},
		map[string]any{"type": "text", "text": "part2"},
	}
	if s := contentToString(arr); s != "part1part2" {
		t.Errorf("array: got %q", s)
	}
	// Nil.
	if s := contentToString(nil); s != "" {
		t.Errorf("nil: got %q", s)
	}
}

func TestLangfuseClientBatching(t *testing.T) {
	var mu sync.Mutex
	var received []json.RawMessage

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/public/ingestion" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		// Verify basic auth.
		user, pass, ok := r.BasicAuth()
		if !ok || user != "pk-test" || pass != "sk-test" {
			t.Errorf("bad auth: user=%q pass=%q ok=%v", user, pass, ok)
		}

		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, body)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer server.Close()

	client := NewLangfuseClient(server.URL, "pk-test", "sk-test")

	// Send a trace and generation.
	client.SendTrace("trace-1", "test trace", "session-1", "10.0.0.1", time.Now(), nil)
	client.SendGeneration(GenerationEvent{
		ID:      "gen-1",
		TraceID: "trace-1",
		Name:    "openai/gpt-4o",
		Model:   "gpt-4o",
		StartTime: time.Now(),
		EndTime:   time.Now(),
	})

	// Close to flush.
	client.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("no batches received")
	}

	// Parse the first batch.
	var batch struct {
		Batch []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"batch"`
	}
	if err := json.Unmarshal(received[0], &batch); err != nil {
		t.Fatalf("failed to parse batch: %v", err)
	}
	if len(batch.Batch) < 2 {
		t.Fatalf("batch has %d events, want >= 2", len(batch.Batch))
	}

	// Verify event types.
	types := make(map[string]bool)
	for _, e := range batch.Batch {
		types[e.Type] = true
	}
	if !types["trace-create"] {
		t.Error("missing trace-create event")
	}
	if !types["generation-create"] {
		t.Error("missing generation-create event")
	}
}

func TestObserverProcessEntry(t *testing.T) {
	var mu sync.Mutex
	var received []json.RawMessage

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, body)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer server.Close()

	obs := &Observer{
		endpoints: DefaultEndpoints(),
		langfuse:  NewLangfuseClient(server.URL, "pk", "sk"),
	}

	// Create a log entry simulating an OpenAI API call.
	entry := proxylog.Entry{
		SkillID:   "test-skill",
		SourceIP:  "10.0.0.5",
		Method:    "POST",
		Host:      "api.openai.com",
		Path:      "/v1/chat/completions",
		Status:    "allowed",
		Detail:    "200 OK",
		Duration:  150,
		Timestamp: time.Now(),
		HasFullLog: true,
		FullDetail: &proxylog.FullDetail{
			RequestBody: `{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`,
			ResponseBody: `{"choices":[{"message":{"content":"Hi!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`,
			ResponseStatus: 200,
		},
	}

	obs.ProcessEntry(entry)
	obs.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("no events received by Langfuse")
	}
}

func TestObserverSkipsNonLLM(t *testing.T) {
	obs := &Observer{
		endpoints: DefaultEndpoints(),
		langfuse:  &LangfuseClient{events: make(chan langfuseEvent, 100), done: make(chan struct{})},
	}

	// Non-LLM entry should be skipped.
	entry := proxylog.Entry{
		Method:    "GET",
		Host:      "example.com",
		Path:      "/api/data",
		Status:    "allowed",
		Timestamp: time.Now(),
		FullDetail: &proxylog.FullDetail{
			RequestBody:  `{"key":"value"}`,
			ResponseBody: `{"data":"test"}`,
		},
	}

	obs.ProcessEntry(entry)

	// Check no events were queued.
	if len(obs.langfuse.events) != 0 {
		t.Errorf("expected 0 events for non-LLM request, got %d", len(obs.langfuse.events))
	}
}

func TestObserverNilSafe(t *testing.T) {
	// Nil observer should not panic.
	var obs *Observer
	obs.ProcessEntry(proxylog.Entry{})
	obs.Close()
}
