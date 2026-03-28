package observability

import (
	"crypto/rand"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/config"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

// Observer receives proxy log entries and forwards LLM-related ones
// to the configured observability backend (Langfuse).
type Observer struct {
	endpoints []LLMEndpoint
	langfuse  *LangfuseClient
}

// NewFromConfig creates a new Observer from the application config. Returns nil if observability is disabled.
func NewFromConfig(cfg config.ObservabilityConfig) *Observer {
	if !cfg.Enabled {
		return nil
	}
	if cfg.LangfuseHost == "" || cfg.LangfusePublicKey == "" || cfg.LangfuseSecretKey == "" {
		log.Printf("[observability] Disabled: missing Langfuse configuration")
		return nil
	}

	endpoints := make([]LLMEndpoint, 0, len(cfg.LLMEndpoints))
	for _, ep := range cfg.LLMEndpoints {
		endpoints = append(endpoints, LLMEndpoint{
			Host:       ep.Host,
			PathPrefix: ep.PathPrefix,
			Provider:   Provider(ep.Provider),
		})
	}
	if len(endpoints) == 0 {
		endpoints = DefaultEndpoints()
	}

	log.Printf("[observability] Enabled: sending to Langfuse at %s with %d LLM endpoints", cfg.LangfuseHost, len(endpoints))
	return &Observer{
		endpoints: endpoints,
		langfuse:  NewLangfuseClient(cfg.LangfuseHost, cfg.LangfusePublicKey, cfg.LangfuseSecretKey),
	}
}

// Close shuts down the observer and flushes pending events.
func (o *Observer) Close() {
	if o != nil && o.langfuse != nil {
		o.langfuse.Close()
	}
}

// ProcessEntry checks if a log entry is an LLM API call and forwards it to Langfuse.
// Called asynchronously by the Logger observer hook.
func (o *Observer) ProcessEntry(entry proxylog.Entry) {
	if o == nil || entry.FullDetail == nil {
		return
	}

	// Only process successful requests with full logging data.
	if entry.Status != "allowed" || entry.FullDetail.RequestBody == "" {
		return
	}

	// Check if this is a known LLM endpoint.
	ep, ok := DetectLLMEndpoint(entry.Host, entry.Path, o.endpoints)
	if !ok {
		return
	}

	// Parse the LLM request.
	model, inputMsgs := ParseLLMRequest(ep.Provider, entry.FullDetail.RequestBody)
	if model == "" && len(inputMsgs) == 0 {
		return // Not a parseable LLM request
	}

	// Parse the LLM response.
	output, inputTokens, outputTokens, totalTokens, finishReason := ParseLLMResponse(ep.Provider, entry.FullDetail.ResponseBody)

	// For Gemini, model is in the URL path (e.g., /v1beta/models/gemini-pro:generateContent).
	if model == "" && ep.Provider == ProviderGemini {
		model = extractGeminiModel(entry.Path)
	}

	// Generate IDs for trace and generation.
	traceID := generateID()
	genID := generateID()

	startTime := entry.Timestamp.Add(-time.Duration(entry.Duration) * time.Millisecond)
	endTime := entry.Timestamp

	// Use skill ID as session ID for grouping agent LLM calls.
	sessionID := entry.SkillID

	// Send trace event.
	o.langfuse.SendTrace(
		traceID,
		fmt.Sprintf("%s %s%s", entry.Method, entry.Host, entry.Path),
		sessionID,
		entry.SourceIP,
		startTime,
		map[string]any{
			"provider": string(ep.Provider),
			"host":     entry.Host,
			"path":     entry.Path,
		},
	)

	// Send generation event.
	o.langfuse.SendGeneration(GenerationEvent{
		ID:           genID,
		TraceID:      traceID,
		Name:         fmt.Sprintf("%s/%s", ep.Provider, model),
		Model:        model,
		StartTime:    startTime,
		EndTime:      endTime,
		Input:        inputMsgs,
		Output:       output,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		TotalTokens:  totalTokens,
		StatusCode:   entry.FullDetail.ResponseStatus,
		Metadata: map[string]any{
			"provider":      string(ep.Provider),
			"finish_reason": finishReason,
			"source_ip":     entry.SourceIP,
			"skill_id":      entry.SkillID,
			"duration_ms":   entry.Duration,
		},
	})

	log.Printf("[observability] Forwarded LLM call: provider=%s model=%s tokens=%d/%d source=%s",
		ep.Provider, model, inputTokens, outputTokens, entry.SourceIP)
}

// extractGeminiModel extracts the model name from a Gemini API path.
// Example: /v1beta/models/gemini-pro:generateContent -> gemini-pro
func extractGeminiModel(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "models" && i+1 < len(parts) {
			model := parts[i+1]
			// Strip the method suffix (e.g., ":generateContent")
			if idx := strings.Index(model, ":"); idx >= 0 {
				model = model[:idx]
			}
			return model
		}
	}
	return ""
}

// generateID returns a random hex ID suitable for Langfuse trace/generation IDs.
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
