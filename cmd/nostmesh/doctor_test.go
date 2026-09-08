package main

import (
	"strings"
	"testing"

	"github.com/luizosorio/nostmesh/internal/config"
)

// doctor reports a prefix every peer would refuse.
//
// An announcement nobody accepts is worse than one nobody configured: the
// operator believes the subnet is reachable, the announcement goes out, and
// every receiver drops it for a reason this node never learns.
func TestDoctorRefusesAnUnroutableAdvertisement(t *testing.T) {
	cfg := config.Default()
	cfg.Routes.Advertise = []string{"127.0.0.0/8"}

	result := checkAdvertisedRoutes(cfg)

	if result.Status != statusError {
		t.Errorf("status = %v, want fail for a loopback advertisement", result.Status)
	}
	if !strings.Contains(result.Detail, "127.0.0.0/8") {
		t.Errorf("the failure does not name the prefix: %s", result.Detail)
	}
}

// A default route is refused, whatever else is configured.
func TestDoctorRefusesADefaultRouteAdvertisement(t *testing.T) {
	cfg := config.Default()
	cfg.Routes.Advertise = []string{"0.0.0.0/0"}

	if result := checkAdvertisedRoutes(cfg); result.Status != statusError {
		t.Errorf("status = %v, want fail for a default route", result.Status)
	}
}

// A prefix covering this node's own overlay address is refused.
//
// It would black-hole the traffic the operator is trying to reach.
func TestDoctorRefusesAdvertisingItsOwnAddresses(t *testing.T) {
	cfg := config.Default()
	cfg.Peers = []config.Peer{{OverlayAddress: "100.96.0.2/32"}}
	cfg.Routes.Advertise = []string{"100.96.0.0/16"}

	if result := checkAdvertisedRoutes(cfg); result.Status != statusError {
		t.Errorf("status = %v, want fail for a prefix covering a local address", result.Status)
	}
}

// An ordinary advertisement passes, so the refusals above mean something.
func TestDoctorAcceptsAnOrdinaryAdvertisement(t *testing.T) {
	cfg := config.Default()
	cfg.Routes.Advertise = []string{"10.20.30.0/24", "192.168.5.0/24"}

	result := checkAdvertisedRoutes(cfg)
	if result.Status != statusOK {
		t.Errorf("status = %v (%s), want ok", result.Status, result.Detail)
	}
	if !strings.Contains(result.Detail, "2") {
		t.Errorf("the detail does not say how many are offered: %s", result.Detail)
	}
}

// A node offering nothing is reported as such rather than as a problem.
func TestDoctorAcceptsANodeThatOffersNothing(t *testing.T) {
	if result := checkAdvertisedRoutes(config.Default()); result.Status != statusOK {
		t.Errorf("status = %v, want ok for a node that advertises nothing", result.Status)
	}
}
