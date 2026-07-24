package service

import (
	"path/filepath"
	"strings"
	"testing"
	"x-ui/database"
	"x-ui/database/model"
)

func TestInboundTag(t *testing.T) {
	if got := inboundTag(12345); got != "inbound-12345" {
		t.Fatalf("inboundTag() = %q, want %q", got, "inbound-12345")
	}
}

func TestAddInboundGeneratesTagFromPort(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skip("go-sqlite3 runtime is unavailable with CGO disabled")
		}
		t.Fatalf("InitDB() error = %v", err)
	}
	t.Cleanup(func() {
		if err := database.CloseDB(); err != nil {
			t.Errorf("CloseDB() error = %v", err)
		}
	})

	inbound := &model.Inbound{
		Port:           12345,
		Protocol:       model.VMess,
		Settings:       `{}`,
		StreamSettings: `{}`,
		Sniffing:       `{}`,
		Tag:            "caller-provided-tag",
	}
	service := &InboundService{}
	if err := service.AddInbound(inbound); err != nil {
		t.Fatalf("AddInbound() error = %v", err)
	}

	saved, err := service.GetInbound(inbound.Id)
	if err != nil {
		t.Fatalf("GetInbound() error = %v", err)
	}
	if saved.Tag != "inbound-12345" {
		t.Fatalf("saved tag = %q, want %q", saved.Tag, "inbound-12345")
	}
}
