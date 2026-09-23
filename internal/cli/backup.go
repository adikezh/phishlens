package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/phishlens/phishlens/internal/store"
)

func newBackupCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Создать консистентный snapshot SQLite",
		PreRunE: func(*cobra.Command, []string) error {
			if out == "" {
				return fmt.Errorf("--out is required")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			if err := store.BackupSQLite(cmd.Context(), cfg.Storage.DSN, out); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "SQLite backup written: %s\n", out)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "output snapshot path")
	return cmd
}

func newRestoreCmd() *cobra.Command {
	var in string
	var force bool
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Проверить и восстановить SQLite snapshot",
		PreRunE: func(*cobra.Command, []string) error {
			if in == "" {
				return fmt.Errorf("--in is required")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return err
			}
			if err := store.RestoreSQLite(context.Background(), cfg.Storage.DSN, in, force); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "SQLite backup restored: %s\n", in)
			return nil
		},
	}
	cmd.Flags().StringVar(&in, "in", "", "input snapshot path")
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing database")
	return cmd
}
