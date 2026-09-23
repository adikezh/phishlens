package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

// SendEmailReply sends a short, privacy-safe verdict without quoting the
// submitted message. SMTP is deliberately opt-in and requires explicit host,
// sender and password configuration.
func SendEmailReply(ctx context.Context, cfg config.IMAP, to string, sub *domain.Submission) error {
	if cfg.SMTPHost == "" || cfg.SMTPFrom == "" {
		return errors.New("email reply: smtp_host and smtp_from are required")
	}
	parsed, err := mail.ParseAddress(to)
	if err != nil || parsed.Address == "" || strings.ContainsAny(parsed.Address, "\r\n") {
		return errors.New("email reply: invalid recipient")
	}
	port := cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("email reply: connect: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("email reply: smtp: %w", err)
	}
	defer client.Close()
	if port == 465 {
		if err := client.StartTLS(&tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("email reply: tls: %w", err)
		}
	} else if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("email reply: starttls: %w", err)
		}
	}
	password := os.Getenv(cfg.SMTPPasswordEnv)
	if cfg.SMTPUser != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.SMTPUser, password, cfg.SMTPHost)); err != nil {
			return fmt.Errorf("email reply: auth: %w", err)
		}
	}
	if err := client.Mail(cfg.SMTPFrom); err != nil {
		return fmt.Errorf("email reply: mail: %w", err)
	}
	if err := client.Rcpt(parsed.Address); err != nil {
		return fmt.Errorf("email reply: recipient: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("email reply: data: %w", err)
	}
	_, writeErr := fmt.Fprint(w, replyMessage(cfg.SMTPFrom, parsed.Address, sub))
	closeErr := w.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return client.Quit()
}

func replyMessage(from, to string, sub *domain.Submission) string {
	verdict := "unknown"
	score := 0
	var explanations []string
	if sub != nil && sub.Result != nil {
		verdict = string(sub.Result.Verdict)
		score = sub.Result.Score
		for _, signal := range sub.Result.Signals {
			explanations = append(explanations, sanitizeHeader(signal.Explanation))
			if len(explanations) == 5 {
				break
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: [PhishLens] Результат проверки\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nВердикт: %s\nСкор: %d/100\n", sanitizeHeader(from), sanitizeHeader(to), verdict, score)
	if len(explanations) > 0 {
		b.WriteString("\nКлючевые признаки:\n")
		for _, explanation := range explanations {
			b.WriteString("- ")
			b.WriteString(explanation)
			b.WriteByte('\n')
		}
	}
	b.WriteString("\nОригинальное письмо не цитируется. Подробности доступны в PhishLens.\n")
	return b.String()
}

func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.Join(strings.Fields(s), " ")
}
