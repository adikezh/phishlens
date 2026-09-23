// Package domain holds the core data model (ТЗ §3): Submission, ParsedMail,
// Signal and Analysis. It has no dependencies on other internal packages so
// every layer (parse, signals, score, store, httpapi) can share it.
package domain

import (
	"strings"
	"time"
)

// Channel is where a submission came from.
type Channel string

const (
	ChannelWeb      Channel = "web"
	ChannelAPI      Channel = "api"
	ChannelOutlook  Channel = "outlook"
	ChannelGmail    Channel = "gmail"
	ChannelIMAP     Channel = "imap"
	ChannelTelegram Channel = "telegram"
	ChannelCLI      Channel = "cli"
)

// Kind is the input format.
type Kind string

const (
	KindText  Kind = "text"
	KindEML   Kind = "eml"
	KindMSG   Kind = "msg"
	KindImage Kind = "image"
	KindPDF   Kind = "pdf"
)

// Status is the review lifecycle of a submission (F-4.6).
type Status string

const (
	StatusProcessing     Status = "processing"
	StatusAnalyzed       Status = "analyzed"
	StatusInReview       Status = "in_review"
	StatusConfirmedPhish Status = "confirmed_phish"
	StatusConfirmedClean Status = "confirmed_clean"
	StatusEscalated      Status = "escalated"
)

// Verdict is the final classification (F-4.5.2).
type Verdict string

const (
	VerdictPhishing    Verdict = "phishing"
	VerdictSuspicious  Verdict = "suspicious"
	VerdictClean       Verdict = "clean"
	VerdictNeedsReview Verdict = "needs_review"
)

// Rank orders verdicts by severity for min_verdict comparisons (clean < suspicious < needs_review < phishing).
func (v Verdict) Rank() int {
	switch v {
	case VerdictClean:
		return 0
	case VerdictSuspicious:
		return 1
	case VerdictNeedsReview:
		return 2
	case VerdictPhishing:
		return 3
	}
	return -1
}

// Category groups signals (ТЗ §4.2).
type Category string

const (
	CategoryHeader     Category = "header"
	CategoryAuth       Category = "auth"
	CategoryDomain     Category = "domain"
	CategoryLink       Category = "link"
	CategoryAttachment Category = "attachment"
	CategoryContent    Category = "content"
	CategoryBrand      Category = "brand"
	CategoryReputation Category = "reputation"
	CategorySemantic   Category = "semantic"
)

// Source says which subsystem produced a signal.
type Source string

const (
	SourceHeuristic Source = "heuristic"
	SourceDNS       Source = "dns"
	SourceTI        Source = "ti"
	SourceLLM       Source = "llm"
)

// AttackType classifies the campaign.
type AttackType string

const (
	AttackCredentialHarvesting AttackType = "credential_harvesting"
	AttackMalware              AttackType = "malware"
	AttackBEC                  AttackType = "bec"
	AttackInvoiceFraud         AttackType = "invoice_fraud"
	AttackExtortion            AttackType = "extortion"
	AttackSpam                 AttackType = "spam"
	AttackNone                 AttackType = "none"
)

// ValidAttackType reports whether s is a known attack type (used to validate LLM output).
func ValidAttackType(s string) bool {
	switch AttackType(s) {
	case AttackCredentialHarvesting, AttackMalware, AttackBEC, AttackInvoiceFraud, AttackExtortion, AttackSpam, AttackNone:
		return true
	}
	return false
}

// Submission is one analysed item.
type Submission struct {
	ID          string      `json:"id"`
	Channel     Channel     `json:"channel"`
	SubmittedBy string      `json:"submitted_by,omitempty"`
	Kind        Kind        `json:"kind"`
	ReceivedAt  time.Time   `json:"received_at"`
	Message     *ParsedMail `json:"message,omitempty"`
	Result      *Analysis   `json:"result,omitempty"`
	Status      Status      `json:"status"`
	ReviewedBy  string      `json:"reviewed_by,omitempty"`
	ReviewedAt  time.Time   `json:"reviewed_at,omitempty"`
	Department  string      `json:"department,omitempty"`
	OrgID       string      `json:"org_id,omitempty"`
}

// Address is a parsed mailbox.
type Address struct {
	Display string `json:"display,omitempty"`
	Addr    string `json:"addr,omitempty"`
	Domain  string `json:"domain,omitempty"`
}

// IsZero reports whether no address was present.
func (a Address) IsZero() bool { return a.Addr == "" && a.Display == "" }

// String renders "Display <addr>".
func (a Address) String() string {
	switch {
	case a.Display != "" && a.Addr != "":
		return a.Display + " <" + a.Addr + ">"
	case a.Addr != "":
		return a.Addr
	default:
		return a.Display
	}
}

// ReceivedHop is one parsed Received: header.
type ReceivedHop struct {
	Raw       string    `json:"raw"`
	From      string    `json:"from,omitempty"`
	By        string    `json:"by,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// AuthResult is a normalised SPF/DKIM/DMARC/ARC outcome.
type AuthResult string

const (
	AuthPass      AuthResult = "pass"
	AuthFail      AuthResult = "fail"
	AuthSoftFail  AuthResult = "softfail"
	AuthNone      AuthResult = "none"
	AuthNeutral   AuthResult = "neutral"
	AuthTempError AuthResult = "temperror"
	AuthPermError AuthResult = "permerror"
	AuthUnknown   AuthResult = ""
)

// AuthResults holds authentication outcomes and where they came from.
type AuthResults struct {
	SPF    AuthResult `json:"spf,omitempty"`
	DKIM   AuthResult `json:"dkim,omitempty"`
	DMARC  AuthResult `json:"dmarc,omitempty"`
	ARC    AuthResult `json:"arc,omitempty"`
	Source string     `json:"source,omitempty"` // header | own | ""
	Raw    string     `json:"raw,omitempty"`
}

// AllPass is true when SPF, DKIM and DMARC all passed.
func (a AuthResults) AllPass() bool {
	return a.SPF == AuthPass && a.DKIM == AuthPass && a.DMARC == AuthPass
}

// Link is a hyperlink found in the body.
type Link struct {
	Href        string   `json:"href"`
	Text        string   `json:"text,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	Port        string   `json:"port,omitempty"`
	IsIP        bool     `json:"is_ip,omitempty"`
	IsShortener bool     `json:"is_shortener,omitempty"`
	Punycode    bool     `json:"punycode,omitempty"`
	Mismatch    bool     `json:"mismatch,omitempty"` // anchor text is a URL/domain that differs from href
	Redirects   []string `json:"redirects,omitempty"`
}

// Attachment is metadata only — content is never persisted or executed (ТЗ §11).
type Attachment struct {
	Name              string   `json:"name"`
	MIME              string   `json:"mime,omitempty"`
	Size              int64    `json:"size"`
	SHA256            string   `json:"sha256,omitempty"`
	Ext               string   `json:"ext,omitempty"`
	MacroDetected     bool     `json:"macro_detected,omitempty"`
	IsArchive         bool     `json:"is_archive,omitempty"`
	PasswordProtected bool     `json:"password_protected,omitempty"`
	NestedNames       []string `json:"nested_names,omitempty"`
	HasActiveContent  bool     `json:"has_active_content,omitempty"` // HTML attachment with <script>/<form>
}

// InlineImage is an embedded or uploaded image (for OCR / logo matching).
type InlineImage struct {
	ContentID string   `json:"content_id,omitempty"`
	MIME      string   `json:"mime,omitempty"`
	Size      int64    `json:"size"`
	SHA256    string   `json:"sha256,omitempty"`
	PHash     string   `json:"phash,omitempty"`
	Colors    []string `json:"colors,omitempty"`
	Width     int      `json:"width,omitempty"`
	Height    int      `json:"height,omitempty"`
}

// PDFInfo is static, non-rendering PDF evidence. The parser never executes
// JavaScript, opens links, or extracts embedded files.
type PDFInfo struct {
	Pages         int      `json:"pages,omitempty"`
	URLs          []string `json:"urls,omitempty"`
	HasJavaScript bool     `json:"has_javascript,omitempty"`
	HasOpenAction bool     `json:"has_open_action,omitempty"`
	HasAutoAction bool     `json:"has_additional_actions,omitempty"`
	HasForms      bool     `json:"has_forms,omitempty"`
	HasEmbedded   bool     `json:"has_embedded_files,omitempty"`
}

// ParsedMail is the normalised representation every input converges to.
type ParsedMail struct {
	// Raw is kept only for in-process authentication checks. It is intentionally
	// excluded from JSON/storage so Community mode never persists the message.
	Raw         []byte              `json:"-"`
	Headers     map[string][]string `json:"headers,omitempty"`
	From        Address             `json:"from"`
	ReplyTo     Address             `json:"reply_to,omitempty"`
	ReturnPath  Address             `json:"return_path,omitempty"`
	To          []Address           `json:"to,omitempty"`
	CC          []Address           `json:"cc,omitempty"`
	Subject     string              `json:"subject,omitempty"`
	Date        time.Time           `json:"date,omitempty"`
	Received    []ReceivedHop       `json:"received,omitempty"`
	AuthResults AuthResults         `json:"auth_results"`
	TextBody    string              `json:"text_body,omitempty"`
	HTMLBody    string              `json:"html_body,omitempty"`
	Links       []Link              `json:"links,omitempty"`
	Attachments []Attachment        `json:"attachments,omitempty"`
	Images      []InlineImage       `json:"images,omitempty"`
	Language    string              `json:"language,omitempty"`
	OCRText     string              `json:"ocr_text,omitempty"`
	PDF         *PDFInfo            `json:"pdf,omitempty"`
}

// Header returns the first value of a header (case-insensitive canonical key).
func (m *ParsedMail) Header(name string) string {
	if m == nil || m.Headers == nil {
		return ""
	}
	for k, v := range m.Headers {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// LinkDomains returns unique link hosts in order of appearance.
func (m *ParsedMail) LinkDomains() []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range m.Links {
		if l.Domain == "" || seen[l.Domain] {
			continue
		}
		seen[l.Domain] = true
		out = append(out, l.Domain)
	}
	return out
}

// Text returns the best available plain text for content analysis.
func (m *ParsedMail) Text() string {
	if m.TextBody != "" {
		return m.TextBody
	}
	return m.OCRText
}

// Signal is one weighted piece of evidence (ТЗ §2, §3).
type Signal struct {
	ID          string   `json:"id"`       // "header.replyto_mismatch"
	Category    Category `json:"category"` // header | auth | ...
	Weight      int      `json:"weight"`   // −40 … +100
	Confidence  float64  `json:"confidence"`
	Evidence    string   `json:"evidence,omitempty"`
	Explanation string   `json:"explanation,omitempty"`
	Source      Source   `json:"source"`
}

// Contribution is the signal's share of the score.
func (s Signal) Contribution() float64 { return float64(s.Weight) * s.Confidence }

// BrandMatch is the brand the message imitates or legitimately belongs to.
type BrandMatch struct {
	Name     string  `json:"name"`
	Locale   string  `json:"locale,omitempty"`
	Method   string  `json:"method"` // domain | domain_similarity | link_similarity | keyword | logo
	Score    float64 `json:"score"`
	Official bool    `json:"official"` // sender is on the brand's official/ESP domains
}

// Span is a quoted fragment with the reason it matters.
type Span struct {
	Quote  string `json:"quote"`
	Reason string `json:"reason"`
}

// LLMExplain is the validated LLM output (F-4.4.2). AIGenerated is always true so
// the UI can label it (F-4.4.4).
type LLMExplain struct {
	AIGenerated       bool     `json:"ai_generated"`
	VerdictOpinion    string   `json:"verdict_opinion,omitempty"`
	AttackType        string   `json:"attack_type,omitempty"`
	Summary           string   `json:"summary,omitempty"`
	Highlights        []Span   `json:"highlights,omitempty"`
	Tactics           []string `json:"social_engineering_tactics,omitempty"`
	RecommendedAction string   `json:"recommended_action,omitempty"`
	Questions         []string `json:"questions_for_analyst,omitempty"`
	Model             string   `json:"model,omitempty"`
	Provider          string   `json:"provider,omitempty"`
	PromptHash        string   `json:"prompt_hash,omitempty"`
	LatencyMs         int      `json:"latency_ms,omitempty"`
	Cached            bool     `json:"cached,omitempty"`
}

// Analysis is the outcome of the pipeline.
type Analysis struct {
	Score           int         `json:"score"`
	Verdict         Verdict     `json:"verdict"`
	Confidence      float64     `json:"confidence"`
	Signals         []Signal    `json:"signals"`
	AttackType      AttackType  `json:"attack_type"`
	Brand           *BrandMatch `json:"brand,omitempty"`
	LLM             *LLMExplain `json:"llm,omitempty"`
	Recommendations []string    `json:"recommendations,omitempty"`
	Warnings        []string    `json:"warnings,omitempty"` // degraded stages (TI/LLM unavailable, OCR off…)
	DurationMs      int         `json:"duration_ms"`
	Stages          []Stage     `json:"stages,omitempty"`
}

// Stage records per-stage latency for /metrics and the UI.
type Stage struct {
	Name       string `json:"name"`
	DurationMs int    `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// HasSignal reports whether a signal with the given ID is present.
func (a *Analysis) HasSignal(id string) bool {
	for _, s := range a.Signals {
		if s.ID == id {
			return true
		}
	}
	return false
}
