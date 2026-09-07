package main

import (
	"encoding/json"
	"flag"
	"net/netip"
	"strings"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/policy"
)

func runPolicy(args []string, stdout, stderr *output) int {
	if len(args) == 0 {
		policyUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "explain":
		return runPolicyExplain(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		policyUsage(stdout)
		return exitOK
	default:
		stderr.printf("nostmesh policy: unknown subcommand %q\n\n", args[0])
		policyUsage(stderr)
		return exitUsage
	}
}

func policyUsage(out *output) {
	out.printf("Usage: nostmesh policy <subcommand>\n\nSubcommands:\n")
	out.printf("  explain   Report what policy decides about a peer, and why\n")
}

// runPolicyExplain reports the decision for every action, and what produced it.
//
// It answers the question an operator actually has — "why can this peer not
// connect" — without making them reproduce the conditions to find out. The
// answer comes from calling the same Decide the service calls: an explanation
// computed some other way would be a second implementation of policy, and the
// day the two disagree is the day the explanation is worthless.
//
// Every action is reported rather than one, because a peer can be allowed for a
// session and refused a route, and asking about one hides exactly the
// difference being looked for.
func runPolicyExplain(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("policy explain", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	peerKey := flags.String("peer", "", "peer's Nostr public key, hex (required)")
	prefix := flags.String("prefix", "", "a prefix the peer might announce, to explain the route decision")
	asJSON := flags.Bool("json", false, "print as JSON")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh policy explain --config <path> --peer <pubkey> [--json]\n\n" +
			"Report what local policy decides about a peer, for every action,\n" +
			"and which rule produced each answer. With --prefix, also explain\n" +
			"what would happen if the peer announced that route. Reads\n" +
			"configuration only and changes nothing.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" || *peerKey == "" {
		stderr.printf("nostmesh policy explain: --config and --peer are required\n")
		return exitUsage
	}

	peer, err := domain.ParseNostrPublicKey(*peerKey)
	if err != nil {
		stderr.printf("nostmesh policy explain: %v\n", err)
		return exitError
	}

	var announced netip.Prefix
	if *prefix != "" {
		announced, err = netip.ParsePrefix(*prefix)
		if err != nil {
			stderr.printf("nostmesh policy explain: %v\n", err)
			return exitError
		}
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		stderr.printf("nostmesh policy explain: %v\n", err)
		return exitError
	}

	explained := explainPeer(allowlist, peer)
	if *prefix != "" {
		explained = append(explained, explainRoute(allowlist, peer, announced))
	}

	if *asJSON {
		encoded, err := json.Marshal(explained)
		if err != nil {
			stderr.printf("nostmesh policy explain: %v\n", err)
			return exitError
		}
		stdout.printf("%s\n", encoded)
		return exitOK
	}

	printExplanation(stdout, peer, explained)
	return exitOK
}

// explainedAction is one action's answer, in a shape that serializes cleanly.
//
// A projection rather than the Decision itself: netip.Prefix marshals to a form
// nobody wants to read, and OutcomeDeny is the empty string, which would appear
// in JSON as a missing answer rather than a refusal.
type explainedAction struct {
	Action     string   `json:"action"`
	Outcome    string   `json:"outcome"`
	Reason     string   `json:"reason"`
	Rule       string   `json:"rule,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
}

// explainedActions is every action policy knows about, in a fixed order.
//
// Fixed rather than derived, so two runs over one configuration produce
// identical output. An explanation an operator cannot diff is worth less.
var explainedActions = []policy.Action{
	policy.ActionSession,
	policy.ActionRoute,
	policy.ActionTransit,
}

func explainPeer(allowlist *policy.Allowlist, peer domain.NostrPublicKey) []explainedAction {
	explained := make([]explainedAction, 0, len(explainedActions))

	for _, action := range explainedActions {
		decision := allowlist.Decide(peer, action)

		allowedIPs := make([]string, 0, len(decision.AllowedIPs))
		for _, prefix := range decision.AllowedIPs {
			allowedIPs = append(allowedIPs, prefix.String())
		}

		explained = append(explained, explainedAction{
			Action:     string(action),
			Outcome:    outcomeName(decision.Outcome),
			Reason:     decision.Reason,
			Rule:       decision.Rule,
			AllowedIPs: allowedIPs,
		})
	}

	return explained
}

// explainRoute answers about one prefix the peer might announce.
//
// Distinct from the "route" row above, which says whether the peer may announce
// anything at all. This says what happens to a particular destination, which is
// the question an operator has when a route did not appear — and the only way
// to see a default route's require_confirmation without waiting for a peer to
// send one.
func explainRoute(allowlist *policy.Allowlist, peer domain.NostrPublicKey, prefix netip.Prefix) explainedAction {
	decision := allowlist.DecideRoute(peer, prefix)

	allowedIPs := make([]string, 0, len(decision.AllowedIPs))
	for _, permitted := range decision.AllowedIPs {
		allowedIPs = append(allowedIPs, permitted.String())
	}

	return explainedAction{
		Action:     "route " + prefix.String(),
		Outcome:    outcomeName(decision.Outcome),
		Reason:     decision.Reason,
		Rule:       decision.Rule,
		AllowedIPs: allowedIPs,
	}
}

// outcomeName renders an outcome.
//
// OutcomeDeny is the empty string so that a decision nobody filled in refuses
// (NM-24). That is right for the type and wrong for a reader, who would see a
// blank where the answer belongs.
func outcomeName(outcome policy.Outcome) string {
	if outcome == policy.OutcomeDeny {
		return "deny"
	}
	return string(outcome)
}

func printExplanation(stdout *output, peer domain.NostrPublicKey, explained []explainedAction) {
	stdout.printf("peer %s\n\n", peer.String())

	for _, entry := range explained {
		stdout.printf("%s\n", entry.Action)
		stdout.printf("  outcome: %s\n", entry.Outcome)
		stdout.printf("  reason:  %s\n", entry.Reason)

		// A denial by default is produced by nothing, so the field is empty by
		// design. Saying so beats printing a blank line the reader has to
		// interpret.
		if entry.Rule == "" {
			stdout.printf("  rule:    none matched\n")
		} else {
			stdout.printf("  rule:    %s\n", entry.Rule)
		}

		if len(entry.AllowedIPs) > 0 {
			stdout.printf("  routes:  %s\n", strings.Join(entry.AllowedIPs, ", "))
		}
		stdout.printf("\n")
	}

	stdout.printf("local policy denies by default; this reports configuration, not a running service\n")
}
