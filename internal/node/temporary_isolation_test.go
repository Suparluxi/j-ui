package node_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Suparluxi/j-ui/internal/application"
	"github.com/Suparluxi/j-ui/internal/config"
	"github.com/Suparluxi/j-ui/internal/engine"
	"github.com/Suparluxi/j-ui/internal/firewall"
	"github.com/Suparluxi/j-ui/internal/model"
	nodeservice "github.com/Suparluxi/j-ui/internal/node"
)

type recordingTemporaryRuntime struct {
	last []nodeservice.TemporaryNode
}

func (r *recordingTemporaryRuntime) Reconcile(_ context.Context, nodes []nodeservice.TemporaryNode) error {
	r.last = append(r.last[:0], nodes...)
	return nil
}

func (*recordingTemporaryRuntime) Healthy(context.Context, int64) bool { return true }

func (*recordingTemporaryRuntime) ListenersHealthy(context.Context, model.Node) error { return nil }

func TestTemporaryNodesDoNotEnterMainSingBoxConfiguration(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		DataDir:       filepath.Join(root, "data"),
		ConfigDir:     filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	proxy := &engine.Mock{}
	service := nodeservice.NewService(app.Store, proxy, firewall.Mock{})
	runtime := &recordingTemporaryRuntime{}
	service.ConfigureTemporaryRuntime(runtime)
	regular, err := service.Create(context.Background(), nodeservice.CreateInput{
		Name: "regular", Protocol: model.ProtocolVLESSReality, Listen: "127.0.0.1",
		Port: availableTCPPort(t), Enabled: true, ClientName: "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := app.Store.CreateOutbound(context.Background(), model.Outbound{
		Name: "test outbound", Type: model.OutboundSOCKS5, Server: "127.0.0.1",
		Port: 1080, Enabled: true, ManagedKind: "manual", Status: "unchecked",
	})
	if err != nil {
		t.Fatal(err)
	}
	temporary, err := service.CloneTemporary(
		context.Background(), regular.ID, "temporary", outbound.ID, nil, "manual", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(runtime.last) != 1 || runtime.last[0].Node.ID != temporary.ID {
		t.Fatalf("temporary runtime inputs = %#v", runtime.last)
	}

	var mainConfig struct {
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(proxy.Configuration, &mainConfig); err != nil {
		t.Fatal(err)
	}
	if len(mainConfig.Inbounds) != 1 || mainConfig.Inbounds[0].Tag != "node-"+strconv.FormatInt(regular.ID, 10) {
		t.Fatalf("main sing-box inbounds = %#v, want only regular node", mainConfig.Inbounds)
	}

	beforeDelete := append([]byte(nil), proxy.Configuration...)
	if err := service.Delete(context.Background(), temporary.ID); err != nil {
		t.Fatal(err)
	}
	if string(proxy.Configuration) != string(beforeDelete) {
		t.Fatal("deleting a temporary node changed the main sing-box configuration")
	}
	if len(runtime.last) != 0 {
		t.Fatalf("temporary runtime inputs after delete = %#v", runtime.last)
	}
}
