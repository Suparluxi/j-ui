package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Suparluxi/j-ui/internal/engine"
	"github.com/Suparluxi/j-ui/internal/engine/singbox"
	"github.com/Suparluxi/j-ui/internal/model"
)

// TemporaryNode is the complete runtime input for one residential node.
// Residential nodes are deliberately reconciled outside the main sing-box
// process so their reloads cannot cancel connections on native nodes.
type TemporaryNode struct {
	Node     model.Node
	Clients  []model.Client
	Outbound model.Outbound
}

type TemporaryRuntime interface {
	Reconcile(context.Context, []TemporaryNode) error
	Healthy(context.Context, int64) bool
	ListenersHealthy(context.Context, model.Node) error
}

type SystemTemporaryRuntime struct {
	Binary    string
	ConfigDir string
	Runner    engine.Runner
}

func NewSystemTemporaryRuntime(binary, configDir string) *SystemTemporaryRuntime {
	return &SystemTemporaryRuntime{
		Binary:    binary,
		ConfigDir: configDir,
		Runner:    engine.ExecRunner{},
	}
}

func (r *SystemTemporaryRuntime) Reconcile(ctx context.Context, nodes []TemporaryNode) error {
	if strings.TrimSpace(r.Binary) == "" {
		return errors.New("temporary sing-box runtime has no binary")
	}
	if err := os.MkdirAll(r.ConfigDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(r.ConfigDir, 0o700); err != nil {
		return err
	}
	keep := make(map[int64]bool, len(nodes))
	for _, item := range nodes {
		if TemporarySource(item.Node) == "" || !item.Node.Enabled {
			continue
		}
		if item.Node.ID < 1 {
			return errors.New("temporary node has invalid ID")
		}
		if item.Node.OutboundID == nil || *item.Node.OutboundID != item.Outbound.ID {
			return fmt.Errorf("temporary node %d has an inconsistent outbound", item.Node.ID)
		}
		if err := r.apply(ctx, item); err != nil {
			return fmt.Errorf("apply temporary node %d: %w", item.Node.ID, err)
		}
		keep[item.Node.ID] = true
	}
	if err := r.prune(ctx, keep); err != nil {
		return fmt.Errorf("prune temporary sing-box runtimes: %w", err)
	}
	return nil
}

func (r *SystemTemporaryRuntime) apply(ctx context.Context, item TemporaryNode) error {
	config, err := singbox.GenerateWithOutbounds(
		[]singbox.NodeWithClients{{Node: item.Node, Clients: item.Clients}},
		[]model.Outbound{item.Outbound},
	)
	if err != nil {
		return err
	}
	unit := temporaryUnit(item.Node.ID)
	system := &engine.System{
		Binary:          r.Binary,
		ConfigPath:      filepath.Join(r.ConfigDir, strconv.FormatInt(item.Node.ID, 10)+".json"),
		ServiceUnit:     unit,
		StartIfInactive: true,
		Runner:          r.runner(),
	}
	return system.Apply(ctx, config, listenersForNode(item.Node))
}

func (r *SystemTemporaryRuntime) Healthy(ctx context.Context, nodeID int64) bool {
	system := r.system(nodeID)
	return system.Healthy(ctx)
}

func (r *SystemTemporaryRuntime) ListenersHealthy(ctx context.Context, node model.Node) error {
	return r.system(node.ID).ListenersHealthy(ctx, listenersForNode(node))
}

func (r *SystemTemporaryRuntime) system(nodeID int64) *engine.System {
	return &engine.System{
		Binary:      r.Binary,
		ConfigPath:  filepath.Join(r.ConfigDir, strconv.FormatInt(nodeID, 10)+".json"),
		ServiceUnit: temporaryUnit(nodeID),
		Runner:      r.runner(),
	}
}

func (r *SystemTemporaryRuntime) prune(ctx context.Context, keep map[int64]bool) error {
	output, err := r.runner().Run(ctx, "systemctl", "list-units", "--all", "--plain", "--no-legend",
		"j-ui-residential@*.service")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		nodeID, ok := residentialUnitID(fields[0])
		if !ok || keep[nodeID] {
			continue
		}
		if err := r.stop(ctx, nodeID); err != nil {
			return err
		}
	}
	return nil
}

func (r *SystemTemporaryRuntime) stop(ctx context.Context, nodeID int64) error {
	unit := temporaryUnit(nodeID)
	if _, err := r.runner().Run(ctx, "systemctl", "disable", "--now", unit); err != nil && !missingUnit(err) {
		return fmt.Errorf("stop %s: %w", unit, err)
	}
	_, _ = r.runner().Run(ctx, "systemctl", "reset-failed", unit)
	if err := os.Remove(filepath.Join(r.ConfigDir, strconv.FormatInt(nodeID, 10)+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s configuration: %w", unit, err)
	}
	return nil
}

func (r *SystemTemporaryRuntime) runner() engine.Runner {
	if r.Runner != nil {
		return r.Runner
	}
	return engine.ExecRunner{}
}

func temporaryUnit(nodeID int64) string {
	return "j-ui-residential@" + strconv.FormatInt(nodeID, 10) + ".service"
}

func residentialUnitID(unit string) (int64, bool) {
	const prefix = "j-ui-residential@"
	const suffix = ".service"
	if !strings.HasPrefix(unit, prefix) || !strings.HasSuffix(unit, suffix) {
		return 0, false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(unit, prefix), suffix)
	nodeID, err := strconv.ParseInt(value, 10, 64)
	return nodeID, err == nil && nodeID > 0
}

func missingUnit(err error) bool {
	message := strings.ToLower(err.Error())
	for _, fragment := range []string{"not loaded", "not found", "no such file", "does not exist"} {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}
