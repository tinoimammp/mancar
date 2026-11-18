package daemon

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"text/tabwriter"

	"github.com/tinoimammp/mancar/internal/config"
	"github.com/tinoimammp/mancar/internal/dashboard"
	"github.com/tinoimammp/mancar/internal/store/postgres"
	"github.com/tinoimammp/mancar/migrations"
)

// ---- accounts ("mancard user ...") -------------------------------------------
//
// Account management for the server operator. Unlike the dashboard it needs
// no password confirmation (shell access to the server is the proof), but
// the database still refuses to remove the last active admin.

const userUsage = `Accounts (dashboard sign in):
  mancard user list                          every account: role, email, status, last sign in
  mancard user create NAME [--email ADDRESS] [--admin] [--password-stdin]
                                               add an account; prints a generated password
                                               unless --password-stdin is given
  mancard user password NAME [--password-stdin]
                                               set a new password (role unchanged); signs
                                               the account out everywhere
  mancard user role NAME admin|user          make NAME an admin, or a plain user
  mancard user disable NAME                  block sign in and refuse NAME's tokens
  mancard user enable NAME                   undo disable
  mancard user delete NAME                   delete NAME with their tokens, subdomains,
                                               captured requests and statistics
`

func cmdUser(ctx context.Context, e Env, args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		w := e.Stdout
		code := 0
		if len(args) == 0 {
			w, code = e.Stderr, 2
		}
		fmt.Fprint(w, userUsage)
		return code
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("user "+sub, flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	email := fs.String("email", "", "email address (create)")
	makeAdmin := fs.Bool("admin", false, "create the account as an admin (create)")
	fromStdin := fs.Bool("password-stdin", false, "read the password from the first line of standard input")
	// flags may come before or after NAME
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return 2
		}
		args = fs.Args()
		if len(args) > 0 {
			pos, args = append(pos, args[0]), args[1:]
		}
	}

	want := map[string]int{"list": 0, "create": 1, "password": 1, "role": 2, "disable": 1, "enable": 1, "delete": 1}
	n, ok := want[sub]
	if !ok {
		fmt.Fprintf(e.Stderr, "mancard user: unknown subcommand %q\n\n%s", sub, userUsage)
		return 2
	}
	if len(pos) != n {
		fmt.Fprintf(e.Stderr, "mancard user %s: expected %d argument(s), got %d\n\n%s", sub, n, len(pos), userUsage)
		return 2
	}
	var name string
	if n > 0 {
		name = strings.ToLower(strings.TrimSpace(pos[0]))
		if !usernameRE.MatchString(name) {
			fmt.Fprintln(e.Stderr, "mancard: a username is 1-64 characters from a-z, 0-9, '.', '_' and '-'")
			return 2
		}
	}
	role := ""
	if sub == "role" {
		role = strings.ToLower(pos[1])
		if role != postgres.RoleAdmin && role != postgres.RoleUser {
			fmt.Fprintln(e.Stderr, "mancard user role: the role is admin or user")
			return 2
		}
	}
	var password string
	var generated bool
	if sub == "create" || sub == "password" {
		var code int
		if password, generated, code = readPassword(e, *fromStdin); code != 0 {
			return code
		}
	}

	return withConfig(e, false, func(cfg *config.Config, _ *slog.Logger) int {
		st, err := openStore(ctx, e, cfg)
		if err != nil {
			fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
			return 1
		}
		defer st.Close()
		if err := st.Migrate(ctx, migrations.FS); err != nil {
			fmt.Fprintf(e.Stderr, "mancard: migration failed: %v\n", err)
			return 1
		}
		fail := func(err error) int {
			switch {
			case errors.Is(err, postgres.ErrNotFound):
				fmt.Fprintf(e.Stderr, "mancard: no account named %q (see: mancard user list)\n", name)
			case errors.Is(err, postgres.ErrLastAdmin):
				fmt.Fprintln(e.Stderr, "mancard: that is the last active admin; make another admin first (mancard user role NAME admin)")
			case errors.Is(err, postgres.ErrUsernameTaken):
				fmt.Fprintf(e.Stderr, "mancard: an account named %q already exists\n", name)
			case errors.Is(err, postgres.ErrEmailTaken):
				fmt.Fprintln(e.Stderr, "mancard: an account with that email already exists")
			default:
				fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
			}
			return 1
		}
		if sub == "list" {
			return listUsers(ctx, e, st)
		}
		if sub == "create" {
			hash, err := dashboard.HashPassword(password)
			if err != nil {
				return fail(err)
			}
			r := postgres.RoleUser
			if *makeAdmin {
				r = postgres.RoleAdmin
			}
			addr := postgres.NormalizeEmail(*email)
			if _, err := st.CreateAccount(ctx, postgres.NewAccount{Username: name, Email: addr, PasswordHash: hash, Role: r, Verified: true}); err != nil {
				return fail(err)
			}
			printPassword(e, generated, password)
			fmt.Fprintf(e.Stderr, "Created %s %q.\nDashboard: %s/dashboard/\n", r, name, cfg.PublicURL(cfg.BaseDomain))
			return 0
		}
		a, err := st.AccountByLogin(ctx, name)
		if err != nil {
			return fail(err)
		}
		switch sub {
		case "password":
			hash, err := dashboard.HashPassword(password)
			if err != nil {
				return fail(err)
			}
			if err := st.SetPassword(ctx, a.ID, hash); err != nil {
				return fail(err)
			}
			printPassword(e, generated, password)
			fmt.Fprintf(e.Stderr, "New password set for %q (%s); their dashboard sessions are signed out.\n", name, a.Role)
		case "role":
			if err := st.SetRole(ctx, a.ID, role); err != nil {
				return fail(err)
			}
			fmt.Fprintf(e.Stdout, "%s is now %s (open dashboard sessions follow at once)\n", name, article(role))
		case "disable", "enable":
			if err := st.SetDisabled(ctx, a.ID, sub == "disable"); err != nil {
				return fail(err)
			}
			if sub == "disable" {
				fmt.Fprintf(e.Stdout, "%s is disabled: signed out, and their tokens are refused (agents already connected are dropped within 30 seconds)\n", name)
			} else {
				fmt.Fprintf(e.Stdout, "%s is enabled again; their tokens work again\n", name)
			}
		case "delete":
			if err := st.DeleteAccount(ctx, a.ID); err != nil {
				return fail(err)
			}
			fmt.Fprintf(e.Stdout, "%s deleted, with their tokens, subdomains, captured requests and statistics\n", name)
		}
		st.AddAudit(ctx, postgres.AuditEntry{Actor: "cli", Action: "user." + sub, Target: name, Detail: role})
		return 0
	})
}

func article(role string) string {
	if role == postgres.RoleAdmin {
		return "an admin"
	}
	return "a user"
}

func listUsers(ctx context.Context, e Env, st *postgres.Store) int {
	list, err := st.ListUsers(ctx)
	if err != nil {
		fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
		return 1
	}
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "USERNAME\tROLE\tEMAIL\tSTATUS\tTOKENS\tLAST SIGN IN")
	for _, u := range list {
		mail, status, last := u.Email, "active", "never"
		if mail == "" {
			mail = "-"
		}
		switch {
		case u.DisabledAt != nil:
			status = "disabled"
		case !u.Verified():
			status = "unconfirmed"
		case u.PasswordHash == "":
			status = "no password"
		}
		if u.LastLoginAt != nil {
			last = u.LastLoginAt.UTC().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", u.Username, u.Role, mail, status, u.ActiveTokens, last)
	}
	tw.Flush()
	return 0
}

// readPassword reads the first line of stdin, or generates a strong
// password. It returns a non-zero exit code on failure.
func readPassword(e Env, fromStdin bool) (password string, generated bool, code int) {
	if fromStdin {
		if e.Stdin == nil {
			fmt.Fprintln(e.Stderr, "mancard: no standard input available")
			return "", false, 2
		}
		line, err := bufio.NewReader(io.LimitReader(e.Stdin, 4096)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			fmt.Fprintf(e.Stderr, "mancard: reading password: %v\n", err)
			return "", false, 1
		}
		password = strings.TrimRight(line, "\r\n")
	} else {
		b := make([]byte, 18)
		if _, err := rand.Read(b); err != nil {
			fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
			return "", false, 1
		}
		password, generated = base64.RawURLEncoding.EncodeToString(b), true
	}
	if len([]rune(password)) < dashboard.MinPasswordLength {
		fmt.Fprintf(e.Stderr, "mancard: %v\n", dashboard.ErrWeakPassword)
		return "", false, 2
	}
	return password, generated, 0
}

// printPassword puts a generated password alone on stdout (so it can be
// captured with $(...)) and the warning on stderr.
func printPassword(e Env, generated bool, password string) {
	if !generated {
		return
	}
	fmt.Fprintln(e.Stdout, password)
	fmt.Fprintln(e.Stderr, "The generated password above is shown only once; store it safely.")
}
