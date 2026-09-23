// Package telegram implements the F-4.1.8 Telegram receiver with the Bot API.
// The bot keeps only an in-memory chat-to-organisation binding and sends the
// submitted content through the same Analyzer used by the REST API.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

const (
	maxPhotoBytes = 10 << 20
	pollTimeout   = 25
)

// AnalyzeFunc is the application boundary used by the receiver.
type AnalyzeFunc func(context.Context, app.Request) (*domain.Submission, error)

// Receiver is a Telegram long-polling runner.
type Receiver struct {
	cfg       config.Telegram
	analyze   AnalyzeFunc
	client    *http.Client
	apiBase   string
	bindings  map[int64]string
	bindingsM sync.RWMutex
}

// New builds a receiver. A nil analyzer makes enabled operation fail closed.
func New(cfg config.Telegram, analyze ...AnalyzeFunc) *Receiver {
	var fn AnalyzeFunc
	if len(analyze) > 0 {
		fn = analyze[0]
	}
	return &Receiver{cfg: cfg, analyze: fn, client: &http.Client{Timeout: 35 * time.Second}, apiBase: "https://api.telegram.org", bindings: map[int64]string{}}
}

func (r *Receiver) Name() string { return "telegram" }

type apiEnvelope struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description,omitempty"`
	Result      json.RawMessage `json:"result"`
}

type update struct {
	ID      int64    `json:"update_id"`
	Message *message `json:"message,omitempty"`
}

type message struct {
	Chat    chat        `json:"chat"`
	Text    string      `json:"text,omitempty"`
	Caption string      `json:"caption,omitempty"`
	Photo   []photoSize `json:"photo,omitempty"`
}

type chat struct {
	ID int64 `json:"id"`
}

type photoSize struct {
	FileID string `json:"file_id"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

type fileInfo struct {
	FilePath string `json:"file_path"`
}

// Run polls Telegram until the context is cancelled. Transient API failures
// are retried with a bounded delay; one malformed update cannot stop the bot.
func (r *Receiver) Run(ctx context.Context) error {
	if !r.cfg.Enabled {
		return nil
	}
	token := strings.TrimSpace(os.Getenv(r.cfg.TokenEnv))
	if token == "" {
		return errors.New("telegram: token environment variable is empty")
	}
	if r.analyze == nil {
		return errors.New("telegram: analyzer is not configured")
	}
	var offset int64
	for {
		updates, err := r.getUpdates(ctx, token, offset)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return ctx.Err()
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		for _, u := range updates {
			if u.ID >= offset {
				offset = u.ID + 1
			}
			if err := r.handleUpdate(ctx, token, u); err != nil && !errors.Is(err, context.Canceled) {
				_ = r.sendMessage(ctx, token, u.chatID(), "PhishLens: не удалось обработать сообщение")
			}
		}
	}
}

func (u update) chatID() int64 {
	if u.Message == nil {
		return 0
	}
	return u.Message.Chat.ID
}

func (r *Receiver) getUpdates(ctx context.Context, token string, offset int64) ([]update, error) {
	q := url.Values{"timeout": {strconv.Itoa(pollTimeout)}}
	if offset > 0 {
		q.Set("offset", strconv.FormatInt(offset, 10))
	}
	var out []update
	if err := r.call(ctx, token, "getUpdates", q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Receiver) handleUpdate(ctx context.Context, token string, u update) error {
	if u.Message == nil || u.Message.Chat.ID == 0 {
		return nil
	}
	m := u.Message
	text := strings.TrimSpace(m.Text)
	if strings.HasPrefix(text, "/start") {
		parts := strings.Fields(text)
		if len(parts) < 2 || strings.TrimSpace(parts[1]) == "" {
			return r.sendMessage(ctx, token, m.Chat.ID, "Использование: /start <код организации>")
		}
		org := strings.TrimSpace(parts[1])
		r.bindingsM.Lock()
		r.bindings[m.Chat.ID] = org
		r.bindingsM.Unlock()
		return r.sendMessage(ctx, token, m.Chat.ID, "Чат привязан к организации. Перешлите текст или скриншот письма.")
	}
	r.bindingsM.RLock()
	org := r.bindings[m.Chat.ID]
	r.bindingsM.RUnlock()
	if org == "" {
		return r.sendMessage(ctx, token, m.Chat.ID, "Сначала привяжите чат: /start <код организации>")
	}
	req := app.Request{Channel: domain.ChannelTelegram, OrgID: org, Lang: "ru"}
	switch {
	case text != "":
		req.Kind, req.Data = domain.KindText, []byte(text)
	case len(m.Photo) > 0:
		p := m.Photo[len(m.Photo)-1]
		data, err := r.downloadPhoto(ctx, token, p.FileID)
		if err != nil {
			return err
		}
		req.Kind, req.Data = domain.KindImage, data
	default:
		return r.sendMessage(ctx, token, m.Chat.ID, "Поддерживаются текст и скриншот изображения.")
	}
	sub, err := r.analyze(ctx, req)
	if err != nil {
		return err
	}
	return r.sendMessage(ctx, token, m.Chat.ID, formatVerdict(sub))
}

func formatVerdict(sub *domain.Submission) string {
	if sub == nil || sub.Result == nil {
		return "PhishLens: анализ принят, результат пока недоступен."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "PhishLens: %s (%d/100)\n", sub.Result.Verdict, sub.Result.Score)
	limit := 3
	for _, signal := range sub.Result.Signals {
		if limit == 0 {
			break
		}
		fmt.Fprintf(&b, "• %s\n", signal.Explanation)
		limit--
	}
	return b.String()
}

func (r *Receiver) downloadPhoto(ctx context.Context, token, fileID string) ([]byte, error) {
	q := url.Values{"file_id": {fileID}}
	var out fileInfo
	if err := r.call(ctx, token, "getFile", q, nil, &out); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.apiBase+"/file/bot"+token+"/"+out.FilePath, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("telegram: download photo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("telegram: download photo: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPhotoBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPhotoBytes {
		return nil, errors.New("telegram: photo exceeds 10 MiB")
	}
	return data, nil
}

func (r *Receiver) sendMessage(ctx context.Context, token string, chatID int64, text string) error {
	if chatID == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]any{"chat_id": chatID, "text": text})
	if err != nil {
		return err
	}
	return r.call(ctx, token, "sendMessage", nil, body, nil)
}

func (r *Receiver) call(ctx context.Context, token, method string, query url.Values, body []byte, out any) error {
	endpoint := r.apiBase + "/bot" + token + "/" + method
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, reader)
	if err != nil {
		return err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram: %s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("telegram: %s: status %d", method, resp.StatusCode)
	}
	var envelope apiEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("telegram: %s: decode: %w", method, err)
	}
	if !envelope.OK {
		return fmt.Errorf("telegram: %s: %s", method, envelope.Description)
	}
	if out != nil && len(envelope.Result) > 0 && string(envelope.Result) != "null" {
		if err := json.Unmarshal(envelope.Result, out); err != nil {
			return fmt.Errorf("telegram: %s result: %w", method, err)
		}
	}
	return nil
}
