// Package imap polls an IMAPS reporting mailbox and sends each unseen message
// through the shared PhishLens analyzer. Message bodies are bounded and are
// never logged. Optional reply/move behavior is enabled only by configuration.
package imap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

const maxMessageBytes = 25 << 20

// AnalyzeFunc is the application boundary used by the receiver.
type AnalyzeFunc func(context.Context, app.Request) (*domain.Submission, error)

// ReplyFunc sends a privacy-safe verdict to the original reporter.
type ReplyFunc func(context.Context, string, *domain.Submission) error

// Receiver is an IMAPS polling runner.
type Receiver struct {
	cfg     config.IMAP
	analyze AnalyzeFunc
	reply   ReplyFunc
}

// New builds the receiver. Optional callbacks allow the transport package to
// remain independent from the application's SMTP and analyzer wiring.
func New(cfg config.IMAP, callbacks ...any) *Receiver {
	r := &Receiver{cfg: cfg}
	for _, callback := range callbacks {
		switch fn := callback.(type) {
		case AnalyzeFunc:
			r.analyze = fn
		case ReplyFunc:
			r.reply = fn
		}
	}
	return r
}

func (r *Receiver) Name() string { return "imap" }

func (r *Receiver) Run(ctx context.Context) error {
	if !r.cfg.Enabled {
		return nil
	}
	if strings.TrimSpace(r.cfg.Host) == "" || strings.TrimSpace(r.cfg.User) == "" {
		return errors.New("imap: host and user are required")
	}
	if r.analyze == nil {
		return errors.New("imap: analyzer is not configured")
	}
	password := os.Getenv(r.cfg.PasswordEnv)
	if password == "" {
		return errors.New("imap: password environment variable is empty")
	}
	interval := r.cfg.PollInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	for {
		if err := r.poll(ctx, password); err != nil && !errors.Is(err, context.Canceled) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func (r *Receiver) poll(ctx context.Context, password string) error {
	c, err := imapclient.DialTLS(r.cfg.Host, nil)
	if err != nil {
		return fmt.Errorf("imap: connect: %w", err)
	}
	defer c.Close()
	if err := c.Login(r.cfg.User, password).Wait(); err != nil {
		return fmt.Errorf("imap: login: %w", err)
	}
	defer func() { _ = c.Logout().Wait() }()
	folder := r.cfg.Folder
	if folder == "" {
		folder = "INBOX"
	}
	if _, err := c.Select(folder, nil).Wait(); err != nil {
		return fmt.Errorf("imap: select %q: %w", folder, err)
	}
	search, err := c.Search(&imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagSeen}}, nil).Wait()
	if err != nil {
		return fmt.Errorf("imap: search: %w", err)
	}
	seqs := search.AllSeqNums()
	if len(seqs) == 0 {
		return nil
	}
	fetch := c.Fetch(imap.SeqSetNum(seqs...), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}})
	var processed []uint32
	for {
		message := fetch.Next()
		if message == nil {
			break
		}
		buf, err := message.Collect()
		if err != nil {
			_ = fetch.Close()
			return fmt.Errorf("imap: fetch: %w", err)
		}
		raw := buf.FindBodySection(&imap.FetchItemBodySection{})
		if len(raw) == 0 || len(raw) > maxMessageBytes {
			continue
		}
		if err := r.process(ctx, raw); err != nil {
			continue
		}
		processed = append(processed, message.SeqNum)
	}
	if err := fetch.Close(); err != nil {
		return fmt.Errorf("imap: fetch close: %w", err)
	}
	if len(processed) == 0 {
		return nil
	}
	store := c.Store(imap.SeqSetNum(processed...), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagSeen}, Silent: true}, nil)
	if err := store.Close(); err != nil {
		return fmt.Errorf("imap: mark seen: %w", err)
	}
	if r.cfg.ProcessedFolder != "" {
		// CREATE is intentionally best-effort: the folder may already exist or
		// be managed by the mail provider.
		_ = c.Create(r.cfg.ProcessedFolder, nil).Wait()
		_, _ = c.Move(imap.SeqSetNum(processed...), r.cfg.ProcessedFolder).Wait()
	}
	return nil
}

func (r *Receiver) process(ctx context.Context, raw []byte) error {
	sub, err := r.analyze(ctx, app.Request{Channel: domain.ChannelIMAP, Kind: domain.KindEML, Data: raw, OrgID: r.cfg.OrgID})
	if err != nil {
		return err
	}
	if r.cfg.ReplyWithVerdict && r.reply != nil {
		message, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			return err
		}
		from, err := mail.ParseAddress(message.Header.Get("From"))
		if err != nil || strings.TrimSpace(from.Address) == "" {
			return nil
		}
		return r.reply(ctx, from.Address, sub)
	}
	return nil
}
