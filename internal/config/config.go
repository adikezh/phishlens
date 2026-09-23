// Package config loads configs/config.yaml (ТЗ §8) with viper: YAML file, then
// environment overrides (PL_SECTION_KEY), then struct validation.
package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

// Config is the root configuration.
type Config struct {
	Server       Server       `mapstructure:"server"`
	Storage      Storage      `mapstructure:"storage"`
	Analysis     Analysis     `mapstructure:"analysis"`
	AuthChecks   AuthChecks   `mapstructure:"auth_checks"`
	Reputation   Reputation   `mapstructure:"reputation"`
	OCR          OCR          `mapstructure:"ocr"`
	LLM          LLM          `mapstructure:"llm"`
	Sandbox      Sandbox      `mapstructure:"sandbox"`
	Ingest       Ingest       `mapstructure:"ingest"`
	Integrations Integrations `mapstructure:"integrations"`
	Auth         Auth         `mapstructure:"auth"`
	Log          Log          `mapstructure:"log"`
}

type Server struct {
	Listen       string  `mapstructure:"listen" validate:"required"`
	BaseURL      string  `mapstructure:"base_url"`
	MaxUploadMB  int     `mapstructure:"max_upload_mb" validate:"min=1,max=200"`
	RateLimitRPS float64 `mapstructure:"rate_limit_rps" validate:"min=0"`
	TLS          TLS     `mapstructure:"tls"`
}

// TLS enables HTTPS when both certificate and key files are configured.
type TLS struct {
	CertFile string `mapstructure:"cert"`
	KeyFile  string `mapstructure:"key"`
}

type Storage struct {
	Driver           string    `mapstructure:"driver" validate:"oneof=sqlite postgres"`
	DSN              string    `mapstructure:"dsn" validate:"required"`
	StoreBodies      bool      `mapstructure:"store_bodies"`
	EncryptionKeyEnv string    `mapstructure:"encryption_key_env"`
	Retention        Retention `mapstructure:"retention"`
}

type Retention struct {
	Submissions string `mapstructure:"submissions"` // "90d", "720h"
}

// SubmissionsDuration parses "90d" / "24h" style values. Zero means keep forever.
func (r Retention) SubmissionsDuration() (time.Duration, error) {
	return ParseDuration(r.Submissions)
}

type Thresholds struct {
	Phishing   int `mapstructure:"phishing" validate:"min=1,max=100"`
	Suspicious int `mapstructure:"suspicious" validate:"min=0,max=100"`
}

type Analysis struct {
	Language            string        `mapstructure:"language" validate:"oneof=ru en kz"`
	Timeout             time.Duration `mapstructure:"timeout"`
	Thresholds          Thresholds    `mapstructure:"thresholds"`
	WeightsFile         string        `mapstructure:"weights_file"`
	BrandsFile          string        `mapstructure:"brands_file"`
	DataDir             string        `mapstructure:"data_dir"`
	PromptsDir          string        `mapstructure:"prompts_dir"`
	CustomBrandsEnabled bool          `mapstructure:"custom_brands_enabled"`
}

type AuthChecks struct {
	OwnSPFDKIMDMARC bool   `mapstructure:"own_spf_dkim_dmarc"`
	DNSResolver     string `mapstructure:"dns_resolver"`
}

type Toggle struct {
	Enabled bool `mapstructure:"enabled"`
}

type URLhaus struct {
	Enabled    bool   `mapstructure:"enabled"`
	AuthKeyEnv string `mapstructure:"auth_key_env"`
}

type RDAP struct {
	Enabled  bool          `mapstructure:"enabled"`
	CacheTTL time.Duration `mapstructure:"cache_ttl"`
}

type KeyedService struct {
	Enabled bool   `mapstructure:"enabled"`
	KeyEnv  string `mapstructure:"key_env"`
}

type SafeBrowsing struct {
	Enabled   bool   `mapstructure:"enabled"`
	APIKeyEnv string `mapstructure:"api_key_env"`
}

type VirusTotal struct {
	Enabled         bool   `mapstructure:"enabled"`
	KeyEnv          string `mapstructure:"key_env"`
	AttachmentsOnly bool   `mapstructure:"attachments_only"`
}

type LinkExpansion struct {
	Enabled      bool          `mapstructure:"enabled"`
	MaxRedirects int           `mapstructure:"max_redirects" validate:"min=0,max=20"`
	Timeout      time.Duration `mapstructure:"timeout"`
}

type Reputation struct {
	RDAP          RDAP          `mapstructure:"rdap"`
	DNSBL         []string      `mapstructure:"dnsbl"`
	URLhaus       URLhaus       `mapstructure:"urlhaus"`
	OpenPhish     Toggle        `mapstructure:"openphish"`
	SafeBrowsing  SafeBrowsing  `mapstructure:"safebrowsing"`
	AbuseIPDB     KeyedService  `mapstructure:"abuseipdb"`
	VirusTotal    VirusTotal    `mapstructure:"virustotal"`
	LinkExpansion LinkExpansion `mapstructure:"link_expansion"`
	Timeout       time.Duration `mapstructure:"timeout"`
}

type OCR struct {
	Mode         string `mapstructure:"mode" validate:"oneof=tesseract vision_llm off"`
	TesseractURL string `mapstructure:"tesseract_url"`
}

type LLMProvider struct {
	Name        string `mapstructure:"name" validate:"required"`
	Type        string `mapstructure:"type" validate:"oneof=openai_compatible anthropic ollama"`
	BaseURL     string `mapstructure:"base_url"`
	Model       string `mapstructure:"model" validate:"required"`
	VisionModel string `mapstructure:"vision_model"`
	APIKeyEnv   string `mapstructure:"api_key_env"`
}

type Budget struct {
	USDPerDay    float64 `mapstructure:"usd_per_day"`
	CallsPerHour int     `mapstructure:"calls_per_hour"`
}

type LLM struct {
	Enabled   bool          `mapstructure:"enabled"`
	RedactPII bool          `mapstructure:"redact_pii"`
	Timeout   time.Duration `mapstructure:"timeout"`
	CacheTTL  time.Duration `mapstructure:"cache_ttl"`
	Providers []LLMProvider `mapstructure:"providers" validate:"dive"`
	Budget    Budget        `mapstructure:"budget"`
}

type Sandbox struct {
	Enabled    bool   `mapstructure:"enabled"`
	URL        string `mapstructure:"url"`
	Screenshot bool   `mapstructure:"screenshot"`
}

type IMAP struct {
	Enabled          bool   `mapstructure:"enabled"`
	Host             string `mapstructure:"host"`
	User             string `mapstructure:"user"`
	PasswordEnv      string `mapstructure:"password_env"`
	Folder           string `mapstructure:"folder"`
	ReplyWithVerdict bool   `mapstructure:"reply_with_verdict"`
}

type Graph struct {
	Enabled         bool   `mapstructure:"enabled"`
	TenantID        string `mapstructure:"tenant_id"`
	ClientID        string `mapstructure:"client_id"`
	ClientSecretEnv string `mapstructure:"client_secret_env"`
	Mailbox         string `mapstructure:"mailbox"`
}

type Telegram struct {
	Enabled  bool   `mapstructure:"enabled"`
	TokenEnv string `mapstructure:"token_env"`
}

type Ingest struct {
	IMAP     IMAP     `mapstructure:"imap"`
	Graph    Graph    `mapstructure:"graph"`
	Telegram Telegram `mapstructure:"telegram"`
}

type Wazuh struct {
	Enabled     bool   `mapstructure:"enabled"`
	APIURL      string `mapstructure:"api_url"`
	User        string `mapstructure:"user"`
	PasswordEnv string `mapstructure:"password_env"`
	MinVerdict  string `mapstructure:"min_verdict"`
}

type Webhook struct {
	Enabled   bool   `mapstructure:"enabled"`
	URL       string `mapstructure:"url"`
	SecretEnv string `mapstructure:"secret_env"`
}

type Integrations struct {
	Wazuh   Wazuh   `mapstructure:"wazuh"`
	Webhook Webhook `mapstructure:"webhook"`
	TheHive Toggle  `mapstructure:"thehive"`
}

type OIDC struct {
	Enabled         bool   `mapstructure:"enabled"`
	Issuer          string `mapstructure:"issuer"`
	ClientID        string `mapstructure:"client_id"`
	ClientSecretEnv string `mapstructure:"client_secret_env"`
	RedirectURL     string `mapstructure:"redirect_url"`
}

type Auth struct {
	AnonymousAnalyze bool `mapstructure:"anonymous_analyze"`
	APIKeysEnabled   bool `mapstructure:"api_keys_enabled"`
	OIDC             OIDC `mapstructure:"oidc"`
}

type Log struct {
	Level  string `mapstructure:"level" validate:"oneof=trace debug info warn error"`
	Pretty bool   `mapstructure:"pretty"`
}

// Load reads the config file at path (or searches configs/, ., /etc/phishlens when
// empty), applies PL_* environment overrides and validates the result.
func Load(path string) (*Config, error) {
	v := viper.New()
	setDefaults(v)
	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("configs")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/phishlens")
	}
	v.SetEnvPrefix("PL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		var nf viper.ConfigFileNotFoundError
		if path != "" || !errors.As(err, &nf) {
			return nil, fmt.Errorf("config: read %q: %w", path, err)
		}
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: decode: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Default returns the built-in configuration (used by tests and `analyze` without a file).
func Default() *Config {
	v := viper.New()
	setDefaults(v)
	var cfg Config
	_ = v.Unmarshal(&cfg)
	return &cfg
}

// Validate checks structural constraints.
func (c *Config) Validate() error {
	if err := validator.New().Struct(c); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if c.Analysis.Thresholds.Suspicious >= c.Analysis.Thresholds.Phishing {
		return errors.New("config: analysis.thresholds.suspicious must be lower than phishing")
	}
	if _, err := c.Storage.Retention.SubmissionsDuration(); err != nil {
		return fmt.Errorf("config: storage.retention.submissions: %w", err)
	}
	if (c.Server.TLS.CertFile == "") != (c.Server.TLS.KeyFile == "") {
		return errors.New("config: server.tls.cert and server.tls.key must be configured together")
	}
	return nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.listen", ":8082")
	v.SetDefault("server.base_url", "http://localhost:8082")
	v.SetDefault("server.max_upload_mb", 25)
	v.SetDefault("server.rate_limit_rps", 5.0)

	v.SetDefault("storage.driver", "sqlite")
	v.SetDefault("storage.dsn", "file:data/phishlens.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	v.SetDefault("storage.store_bodies", false)
	v.SetDefault("storage.encryption_key_env", "PL_ENC_KEY")
	v.SetDefault("storage.retention.submissions", "90d")

	v.SetDefault("analysis.language", "ru")
	v.SetDefault("analysis.timeout", "10s")
	v.SetDefault("analysis.thresholds.phishing", 70)
	v.SetDefault("analysis.thresholds.suspicious", 40)
	v.SetDefault("analysis.weights_file", "data/weights.yaml")
	v.SetDefault("analysis.brands_file", "data/brands.yaml")
	v.SetDefault("analysis.data_dir", "data")
	v.SetDefault("analysis.prompts_dir", "prompts")
	v.SetDefault("analysis.custom_brands_enabled", true)

	v.SetDefault("auth_checks.own_spf_dkim_dmarc", true)
	v.SetDefault("auth_checks.dns_resolver", "1.1.1.1:53")

	v.SetDefault("reputation.rdap.enabled", true)
	v.SetDefault("reputation.rdap.cache_ttl", "168h")
	v.SetDefault("reputation.dnsbl", []string{"zen.spamhaus.org"})
	v.SetDefault("reputation.urlhaus.enabled", true)
	v.SetDefault("reputation.urlhaus.auth_key_env", "URLHAUS_AUTH_KEY")
	v.SetDefault("reputation.openphish.enabled", true)
	v.SetDefault("reputation.safebrowsing.enabled", false)
	v.SetDefault("reputation.safebrowsing.api_key_env", "GSB_KEY")
	v.SetDefault("reputation.abuseipdb.enabled", false)
	v.SetDefault("reputation.abuseipdb.key_env", "ABUSEIPDB_KEY")
	v.SetDefault("reputation.virustotal.enabled", false)
	v.SetDefault("reputation.virustotal.key_env", "VT_KEY")
	v.SetDefault("reputation.virustotal.attachments_only", true)
	v.SetDefault("reputation.link_expansion.enabled", true)
	v.SetDefault("reputation.link_expansion.max_redirects", 5)
	v.SetDefault("reputation.link_expansion.timeout", "4s")
	v.SetDefault("reputation.timeout", "3s")

	v.SetDefault("ocr.mode", "off")
	v.SetDefault("ocr.tesseract_url", "http://ocr:8090")

	v.SetDefault("llm.enabled", false)
	v.SetDefault("llm.redact_pii", true)
	v.SetDefault("llm.timeout", "8s")
	v.SetDefault("llm.cache_ttl", "24h")
	v.SetDefault("llm.budget.usd_per_day", 3.0)
	v.SetDefault("llm.budget.calls_per_hour", 300)

	v.SetDefault("sandbox.enabled", false)
	v.SetDefault("sandbox.url", "http://sandbox:9222")
	v.SetDefault("sandbox.screenshot", true)

	v.SetDefault("ingest.imap.enabled", false)
	v.SetDefault("ingest.imap.folder", "INBOX")
	v.SetDefault("ingest.imap.password_env", "IMAP_PASS")
	v.SetDefault("ingest.imap.reply_with_verdict", true)
	v.SetDefault("ingest.graph.enabled", false)
	v.SetDefault("ingest.graph.client_secret_env", "GRAPH_SECRET")
	v.SetDefault("ingest.telegram.enabled", false)
	v.SetDefault("ingest.telegram.token_env", "TG_TOKEN")

	v.SetDefault("integrations.wazuh.enabled", false)
	v.SetDefault("integrations.wazuh.password_env", "WAZUH_PASS")
	v.SetDefault("integrations.wazuh.min_verdict", "suspicious")
	v.SetDefault("integrations.webhook.enabled", false)
	v.SetDefault("integrations.webhook.secret_env", "WEBHOOK_SECRET")
	v.SetDefault("integrations.thehive.enabled", false)

	v.SetDefault("auth.anonymous_analyze", true)
	v.SetDefault("auth.api_keys_enabled", true)
	v.SetDefault("auth.oidc.enabled", false)

	v.SetDefault("log.level", "info")
	v.SetDefault("log.pretty", true)
}

// ParseDuration accepts Go durations plus a "d" (days) suffix; "" or "0" → 0.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid days value %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
