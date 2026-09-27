//go:build exploratory

/*
Copyright 2026 Byeonghoon Yoo.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package exploratory

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/test/cfstub"
)

// g1Fixture builds the attribution inputs TestGatewayStateMachine would see
// for one iteration: a namespace, two candidate tunnels (an explicit sibling
// and the implicit bound tunnel), the matching remote stubs, and the journal.
type g1Fixture struct {
	namespace string
	accountID string
	clusterID string
	gateway   string
	tunnel    string
	bound     string
	hostnames []string
	tunnels   []v1alpha1.CloudflareTunnel
	remotes   []cfstub.Tunnel
}

func g1MachineFixture() *g1Fixture {
	return &g1Fixture{
		namespace: "expl-gw-1",
		accountID: "00000000000000000000000000001001",
		clusterID: "00000000-0000-4000-8000-000000000128",
		gateway:   "gw-1",
		tunnel:    "tun-1",
		bound:     "gw-1",
		hostnames: []string{"app.expl1.example.com", "alt.expl1.example.com"},
	}
}

func (f *g1Fixture) attribution() *g1Attribution {
	return newG1Attribution(f.namespace, f.gateway, f.bound, f.accountID, f.clusterID, f.hostnames, f.tunnels, f.remotes)
}

// liveTunnel adds a live CloudflareTunnel carrying the given Accepted
// condition. A nil accepted models a not-yet-reconciled tunnel.
func (f *g1Fixture) liveTunnel(name string, tunnelID string, accepted *metav1.Condition) {
	tunnel := v1alpha1.CloudflareTunnel{
		ObjectMeta: metav1.ObjectMeta{Namespace: f.namespace, Name: name},
		Status:     v1alpha1.CloudflareTunnelStatus{TunnelID: tunnelID},
	}
	if accepted != nil {
		tunnel.Status.Conditions = []metav1.Condition{*accepted}
	}
	f.tunnels = append(f.tunnels, tunnel)
}

func (f *g1Fixture) deleteTunnel(name string) {
	deleting := metav1.Now()
	for i := range f.tunnels {
		if f.tunnels[i].Name == name {
			f.tunnels[i].DeletionTimestamp = &deleting
		}
	}
}

// remoteTunnel registers a remote tunnel in the stub state, named the way
// desiredTunnelName composes it for crName.
func (f *g1Fixture) remoteTunnel(id string, crName string) {
	f.remotes = append(f.remotes, cfstub.Tunnel{ID: id, Name: f.remoteName(crName)})
}

func (f *g1Fixture) tombstonedRemote(id string, crName string) {
	deleted := time.Now()
	f.remotes = append(f.remotes, cfstub.Tunnel{ID: id, Name: f.remoteName(crName), DeletedAt: &deleted})
}

func g1Accepted(reason string) *metav1.Condition {
	return &metav1.Condition{
		Type:   v1alpha1.CloudflareTunnelConditionAccepted,
		Status: metav1.ConditionTrue,
		Reason: reason,
	}
}

func g1Denied(status metav1.ConditionStatus, reason, message string) *metav1.Condition {
	return &metav1.Condition{
		Type: v1alpha1.CloudflareTunnelConditionAccepted, Status: status,
		Reason: reason, Message: message,
	}
}

func (f *g1Fixture) remoteName(crName string) string {
	return fmt.Sprintf("%s-%s-%s", f.clusterID, f.namespace, crName)
}

func (f *g1Fixture) tunnelPath(id, rest string) string {
	return fmt.Sprintf("/accounts/%s/cfd_tunnel/%s%s", f.accountID, id, rest)
}

func (f *g1Fixture) tokenGet(id string) cfstub.Call {
	return cfstub.Call{Method: http.MethodGet, Path: f.tunnelPath(id, "/token")}
}

func (f *g1Fixture) tunnelCreate(crName string) cfstub.Call {
	return cfstub.Call{Method: http.MethodPost, Path: fmt.Sprintf("/accounts/%s/cfd_tunnel", f.accountID),
		Body: fmt.Sprintf(`{"config_src":"cloudflare","name":%q}`, f.remoteName(crName))}
}

func (f *g1Fixture) dnsPost(id, hostname, owner string) cfstub.Call {
	return cfstub.Call{Method: http.MethodPost, Path: "/zones/zone-1/dns_records",
		Body: fmt.Sprintf(`{"comment":"flareway %s/%s/%s","content":"%s.cfargotunnel.com","name":%q,"type":"CNAME"}`,
			f.clusterID, f.namespace, owner, id, hostname)}
}

func (f *g1Fixture) configPut(id string) cfstub.Call {
	return cfstub.Call{Method: http.MethodPut, Path: f.tunnelPath(id, "/configurations"),
		Body: `{"config":{"ingress":[{"hostname":"app.expl1.example.com","service":"http://127.0.0.1:8080"}]}}`}
}

// g1Check runs the G1 oracle over the journal with per-owner watermarks; a
// missing entry means the tunnel was never evaluated (mark 0).
func (f *g1Fixture) g1Check(t *testing.T, journal []cfstub.Call, ownerMarks map[string]int, sharedMark int) (cfstub.Call, string, bool) {
	t.Helper()
	return f.attribution().unauthorizedProvisioning(journal, ownerMarks, sharedMark)
}

func TestG1Attribution(t *testing.T) {
	t.Run("provisioning classification pins the provisions contract", func(t *testing.T) {
		f := g1MachineFixture()
		a := f.attribution()
		cases := []struct {
			name string
			call cfstub.Call
			want bool
		}{
			{name: "tunnel create", call: f.tunnelCreate("tun-1"), want: true},
			{name: "token fetch", call: f.tokenGet("00000000-0000-0000-0000-000000000001"), want: true},
			{name: "management token", call: cfstub.Call{Method: http.MethodPost, Path: f.tunnelPath("id1", "/management")}, want: true},
			{name: "remote rename", call: cfstub.Call{Method: http.MethodPatch, Path: f.tunnelPath("id1", ""), Body: `{"name":"x"}`}, want: true},
			{name: "dns create", call: f.dnsPost("id1", "app.expl1.example.com", "tun-1"), want: true},
			{name: "config PUT", call: f.configPut("id1"), want: false},
			{name: "dns update", call: cfstub.Call{Method: http.MethodPut, Path: "/zones/zone-1/dns_records/r1", Body: `{"name":"app.expl1.example.com"}`}, want: false},
			{name: "dns delete", call: cfstub.Call{Method: http.MethodDelete, Path: "/zones/zone-1/dns_records/r1"}, want: false},
			{name: "tunnel delete", call: cfstub.Call{Method: http.MethodDelete, Path: f.tunnelPath("id1", "")}, want: false},
			{name: "connections list", call: cfstub.Call{Method: http.MethodGet, Path: f.tunnelPath("id1", "/connections")}, want: false},
			{name: "tunnel GET", call: cfstub.Call{Method: http.MethodGet, Path: f.tunnelPath("id1", "")}, want: false},
			{name: "token verify", call: cfstub.Call{Method: http.MethodGet, Path: "/user/tokens/verify"}, want: false},
			{name: "dns list with hostname query", call: cfstub.Call{Method: http.MethodGet, Path: "/zones/zone-1/dns_records?name.exact=app.expl1.example.com&per_page=1000"}, want: false},
			{name: "config GET", call: cfstub.Call{Method: http.MethodGet, Path: f.tunnelPath("id1", "/configurations")}, want: false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := a.provisioning(tc.call); got != tc.want {
					t.Fatalf("provisioning(%s %s) = %v, want %v", tc.call.Method, tc.call.Path, got, tc.want)
				}
			})
		}
	})

	t.Run("call attribution", func(t *testing.T) {
		cases := []struct {
			name    string
			prepare func(f *g1Fixture)
			call    func(f *g1Fixture) cfstub.Call
			want    string
			wantOK  bool
		}{
			{
				name:    "token fetch resolves by status.tunnelId",
				prepare: func(f *g1Fixture) { f.liveTunnel("tun-1", "id-tun", g1Accepted("Accepted")) },
				call:    func(f *g1Fixture) cfstub.Call { return f.tokenGet("id-tun") },
				want:    "tun-1",
				wantOK:  true,
			},
			{
				name: "remote id resolves by stub name suffix before status commit",
				prepare: func(f *g1Fixture) {
					f.liveTunnel("tun-1", "", nil)
					f.remoteTunnel("id-tun", "tun-1")
				},
				call:   func(f *g1Fixture) cfstub.Call { return f.tokenGet("id-tun") },
				want:   "tun-1",
				wantOK: true,
			},
			{
				name: "tombstoned remote resolves to the owner name",
				prepare: func(f *g1Fixture) {
					f.liveTunnel("gw-1", "", nil)
					f.tombstonedRemote("id-old", "gw-1")
				},
				call:   func(f *g1Fixture) cfstub.Call { return f.tokenGet("id-old") },
				want:   "gw-1",
				wantOK: true,
			},
			{
				name:    "unknown remote id is unattributable",
				prepare: func(f *g1Fixture) { f.liveTunnel("gw-1", "id-gw", g1Accepted("Accepted")) },
				call:    func(f *g1Fixture) cfstub.Call { return f.tokenGet("id-stray") },
				wantOK:  false,
			},
			{
				name:    "create POST resolves by body name suffix without a stub entry",
				prepare: func(f *g1Fixture) { f.liveTunnel("tun-1", "", nil) },
				call:    func(f *g1Fixture) cfstub.Call { return f.tunnelCreate("tun-1") },
				want:    "tun-1",
				wantOK:  true,
			},
			{
				name:    "create POST with foreign name is unattributable",
				prepare: func(f *g1Fixture) { f.liveTunnel("tun-1", "", nil) },
				call: func(f *g1Fixture) cfstub.Call {
					return cfstub.Call{Method: http.MethodPost, Path: fmt.Sprintf("/accounts/%s/cfd_tunnel", f.accountID),
						Body: `{"config_src":"cloudflare","name":"other-cluster-expl-gw-1-stray"}`}
				},
				wantOK: false,
			},
			{
				name: "name suffix does not confuse gw-1 and gw-10 names",
				prepare: func(f *g1Fixture) {
					f.gateway = "gw-10"
					f.bound = "gw-10"
					f.tunnel = "tun-10"
					f.liveTunnel("gw-1", "", nil)
					f.liveTunnel("gw-10", "", nil)
					f.remoteTunnel("id-1", "gw-1")
					f.remoteTunnel("id-10", "gw-10")
				},
				call:   func(f *g1Fixture) cfstub.Call { return f.tokenGet("id-10") },
				want:   "gw-10",
				wantOK: true,
			},
			{
				name:    "DNS create resolves by content tunnel id",
				prepare: func(f *g1Fixture) { f.liveTunnel("tun-1", "id-tun", g1Accepted("Accepted")) },
				call:    func(f *g1Fixture) cfstub.Call { return f.dnsPost("id-tun", "app.expl1.example.com", "gw-1") },
				want:    "tun-1",
				wantOK:  true,
			},
			{
				name: "DNS create resolves a gateway-named comment to the bound tunnel",
				prepare: func(f *g1Fixture) {
					f.bound = "tun-1" // explicit parametersRef binding
					f.liveTunnel("tun-1", "", nil)
				},
				call: func(f *g1Fixture) cfstub.Call {
					return cfstub.Call{Method: http.MethodPost, Path: "/zones/zone-1/dns_records",
						Body: fmt.Sprintf(`{"comment":"flareway %s/%s/gw-1","name":%q}`, f.clusterID, f.namespace, "app.expl1.example.com")}
				},
				want:   "tun-1",
				wantOK: true,
			},
			{
				name: "DNS create resolves a tunnel-named comment directly",
				prepare: func(f *g1Fixture) {
					f.gateway = ""
					f.bound = "tun-1"
					f.liveTunnel("tun-1", "", nil)
				},
				call: func(f *g1Fixture) cfstub.Call {
					return cfstub.Call{Method: http.MethodPost, Path: "/zones/zone-1/dns_records",
						Body: fmt.Sprintf(`{"comment":"flareway %s/%s/tun-1","name":%q}`, f.clusterID, f.namespace, "app.expl1.example.com")}
				},
				want:   "tun-1",
				wantOK: true,
			},
			{
				name:    "hashed comment is unattributable",
				prepare: func(f *g1Fixture) { f.liveTunnel("tun-1", "", nil) },
				call: func(f *g1Fixture) cfstub.Call {
					return cfstub.Call{Method: http.MethodPost, Path: "/zones/zone-1/dns_records",
						Body: `{"comment":"flareway sha256:deadbeef","name":"app.expl1.example.com"}`}
				},
				wantOK: false,
			},
			{
				name:    "DNS create for a foreign owner is unattributable",
				prepare: func(f *g1Fixture) { f.liveTunnel("tun-1", "", nil) },
				call: func(f *g1Fixture) cfstub.Call {
					return cfstub.Call{Method: http.MethodPost, Path: "/zones/zone-1/dns_records",
						Body: fmt.Sprintf(`{"comment":"flareway %s/%s/zzz","name":"app.expl1.example.com"}`, f.clusterID, f.namespace)}
				},
				wantOK: false,
			},
			{
				// Same namespace and a live owner name, but another cluster's
				// marker: only this cluster's comments attribute.
				name:    "DNS create with a foreign cluster ID is unattributable",
				prepare: func(f *g1Fixture) { f.liveTunnel("tun-1", "", nil) },
				call: func(f *g1Fixture) cfstub.Call {
					return cfstub.Call{Method: http.MethodPost, Path: "/zones/zone-1/dns_records",
						Body: fmt.Sprintf(`{"comment":"flareway 00000000-0000-4000-8000-00000000f00d/%s/tun-1","name":"app.expl1.example.com"}`, f.namespace)}
				},
				wantOK: false,
			},
			{
				name:    "PATCH rename resolves by path id not body name",
				prepare: func(f *g1Fixture) { f.liveTunnel("tun-1", "id-tun", g1Accepted("Accepted")) },
				call: func(f *g1Fixture) cfstub.Call {
					return cfstub.Call{Method: http.MethodPatch, Path: f.tunnelPath("id-tun", ""), Body: `{"name":"renamed-remote"}`}
				},
				want:   "tun-1",
				wantOK: true,
			},
			{
				name:    "query string still resolves by path id",
				prepare: func(f *g1Fixture) { f.liveTunnel("tun-1", "id-tun", g1Accepted("Accepted")) },
				call: func(f *g1Fixture) cfstub.Call {
					return cfstub.Call{Method: http.MethodGet, Path: f.tunnelPath("id-tun", "/token") + "?page=2"}
				},
				want:   "tun-1",
				wantOK: true,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				f := g1MachineFixture()
				if tc.prepare != nil {
					tc.prepare(f)
				}
				owner, attributed := f.attribution().callOwner(tc.call(f))
				if attributed != tc.wantOK {
					t.Fatalf("attributed = %v, want %v (owner %q)", attributed, tc.wantOK, owner)
				}
				if attributed && owner != tc.want {
					t.Fatalf("owner = %q, want %q", owner, tc.want)
				}
			})
		}
	})

	t.Run("unauthorized provisioning evaluation", func(t *testing.T) {
		const idTun, idGw = "id-tun", "id-gw"

		// seedIssue128 mirrors the failing journal: explicit tun-1 is Accepted
		// and fully remote-bound; implicit bound gw-1 exists but has never been
		// reconciled (no conditions, no status.tunnelId).
		seedIssue128 := func(t *testing.T) *g1Fixture {
			t.Helper()
			f := g1MachineFixture()
			f.liveTunnel("gw-1", "", nil)
			f.liveTunnel("tun-1", idTun, g1Accepted("Accepted"))
			f.remoteTunnel(idTun, "tun-1")
			return f
		}

		t.Run("accepted sibling calls pass while the bound tunnel has no status", func(t *testing.T) {
			f := seedIssue128(t)
			journal := []cfstub.Call{
				f.tunnelCreate("tun-1"), f.tokenGet(idTun),
				{Method: http.MethodGet, Path: f.tunnelPath(idTun, "/connections")},
				f.configPut(idTun), f.dnsPost(idTun, "app.expl1.example.com", "tun-1"),
			}
			if call, blamed, violated := f.g1Check(t, journal, nil, len(journal)); violated {
				t.Fatalf("G1 violated on %s %s blamed %q; all calls belong to accepted tun-1", call.Method, call.Path, blamed)
			}
		})

		t.Run("the pre-fix predicate fails on the same journal", func(t *testing.T) {
			f := seedIssue128(t)
			journal := []cfstub.Call{f.tokenGet(idTun)}
			// Mirror of the pre-fix check: when the bound tunnel (here gw-1,
			// unreconciled) is unauthorized, every provisions() call in the
			// window fails regardless of which tunnel it belongs to.
			boundCR, boundLive := f.tunnels[0], false
			for i := range f.tunnels {
				if f.tunnels[i].Name == f.bound {
					boundCR, boundLive = f.tunnels[i], true
				}
			}
			if !boundLive || g1TunnelProvisioningPermitted(&boundCR) {
				t.Fatal("fixture must have a live unauthorized bound tunnel")
			}
			violated := false
			a := f.attribution()
			for _, call := range journal {
				if a.provisioning(call) {
					violated = true
				}
			}
			if !violated {
				t.Fatal("pre-fix oracle would not have failed; the regression shape is unproven")
			}
		})

		t.Run("call attributed to an unauthorized tunnel fails while another is bound and accepted", func(t *testing.T) {
			f := g1MachineFixture()
			f.bound = "tun-1" // explicit binding; sibling gw-1 is live but unauthorized
			f.liveTunnel("tun-1", idTun, g1Accepted("Accepted"))
			f.liveTunnel("gw-1", idGw, nil)
			f.remoteTunnel(idGw, "gw-1")
			journal := []cfstub.Call{f.tunnelCreate("gw-1"), f.tokenGet(idGw)}
			call, blamed, violated := f.g1Check(t, journal, nil, len(journal))
			if !violated {
				t.Fatal("gw-1's provisioning calls while gw-1 is unauthorized must fail")
			}
			if blamed != "gw-1" {
				t.Fatalf("blamed %q, want gw-1 (call %s %s)", blamed, call.Method, call.Path)
			}
		})

		t.Run("unattributable provisioning call fails while a live tunnel is unauthorized", func(t *testing.T) {
			f := g1MachineFixture()
			f.liveTunnel("gw-1", "", nil)
			journal := []cfstub.Call{{
				Method: http.MethodPost,
				Path:   "/zones/zone-1/dns_records",
				Body:   `{"name":"app.expl1.example.com","type":"CNAME","content":"foreign.example.com"}`,
			}}
			if _, _, violated := f.g1Check(t, journal, nil, 0); !violated {
				t.Fatal("unattributable DNS create must fail closed while gw-1 is unauthorized")
			}
		})

		t.Run("unattributable call passes when every live tunnel is authorized", func(t *testing.T) {
			f := g1MachineFixture()
			f.liveTunnel("gw-1", "", g1Accepted("Accepted"))
			journal := []cfstub.Call{{
				Method: http.MethodPost,
				Path:   "/zones/zone-1/dns_records",
				Body:   `{"name":"app.expl1.example.com","type":"CNAME","content":"foreign.example.com"}`,
			}}
			if call, blamed, violated := f.g1Check(t, journal, nil, 0); violated {
				t.Fatalf("unattributable call must not fail when no live tunnel is unauthorized: %v %q", call, blamed)
			}
		})

		t.Run("cleanup-reason denials still permit provisioning", func(t *testing.T) {
			for _, reason := range []string{"WaitingForDrain", "WaitingForOwnerDrain", "TargetNotFound"} {
				t.Run(reason, func(t *testing.T) {
					f := g1MachineFixture()
					f.liveTunnel("gw-1", idGw, g1Denied(metav1.ConditionFalse, reason, "draining before teardown"))
					f.remoteTunnel(idGw, "gw-1")
					journal := []cfstub.Call{f.tokenGet(idGw)}
					if call, blamed, violated := f.g1Check(t, journal, nil, len(journal)); violated {
						t.Fatalf("cleanup-reason %s owner must be allowed; violated on %s %s blamed %q", reason, call.Method, call.Path, blamed)
					}
				})
			}
		})

		t.Run("non-cleanup denials fail for the owner itself", func(t *testing.T) {
			for _, reason := range []string{"InvalidAccountRef", "RefNotPermitted", "UnsupportedValue"} {
				t.Run(reason, func(t *testing.T) {
					f := g1MachineFixture()
					f.liveTunnel("gw-1", idGw, g1Denied(metav1.ConditionFalse, reason, `namespace "expl-gw-1" is not granted`))
					f.remoteTunnel(idGw, "gw-1")
					journal := []cfstub.Call{f.tokenGet(idGw)}
					if _, blamed, violated := f.g1Check(t, journal, nil, len(journal)); !violated || blamed != "gw-1" {
						t.Fatalf("denied owner call must fail blamed gw-1; violated=%v blamed=%q", violated, blamed)
					}
				})
			}
		})

		t.Run("calls owned by a deleting or gone tunnel are allowed", func(t *testing.T) {
			f := g1MachineFixture()
			f.liveTunnel("tun-1", idTun, g1Accepted("Accepted"))
			f.liveTunnel("gw-1", "", nil) // unauthorized bound sibling
			f.deleteTunnel("tun-1")
			f.remoteTunnel(idTun, "tun-1")
			journal := []cfstub.Call{f.tokenGet(idTun)}
			if call, blamed, violated := f.g1Check(t, journal, nil, len(journal)); violated {
				t.Fatalf("deleting owner's calls must be allowed; violated on %s %s blamed %q", call.Method, call.Path, blamed)
			}

			// Gone owner still named by the binding: the tombstoned remote
			// resolves to a candidate with no live CR, i.e. cleanup. The shared
			// mark is 0 so only tombstone resolution can excuse the call.
			f2 := g1MachineFixture()
			f2.bound = "tun-1"
			f2.liveTunnel("gw-1", "", nil) // unauthorized live tunnel
			f2.tombstonedRemote("id-old", "tun-1")
			journal = []cfstub.Call{f2.tokenGet("id-old")}
			if call, blamed, violated := f2.g1Check(t, journal, nil, 0); violated {
				t.Fatalf("gone candidate owner's calls must be allowed; violated on %s %s blamed %q", call.Method, call.Path, blamed)
			}
		})

		t.Run("tombstone of a non-candidate owner fails closed", func(t *testing.T) {
			// Tombstones resolve only for candidate names. A remote whose name
			// matches no live, gateway, or bound tunnel is unattributable, so
			// it fails while a live tunnel is unauthorized.
			f := g1MachineFixture()
			f.liveTunnel("gw-1", "", nil)
			f.tombstonedRemote("id-ghost", "ghost-1")
			journal := []cfstub.Call{f.tokenGet("id-ghost")}
			if _, blamed, violated := f.g1Check(t, journal, nil, 0); !violated || blamed != "gw-1" {
				t.Fatalf("non-candidate tombstone must fail closed blamed gw-1; violated=%v blamed=%q", violated, blamed)
			}
		})

		t.Run("calls below the owner watermark are not re-evaluated", func(t *testing.T) {
			f := seedIssue128(t)
			// tun-1 was authorized when its calls were scanned; the mark moved
			// past them. A later denial must not flag the same window.
			for i := range f.tunnels {
				if f.tunnels[i].Name == "tun-1" {
					f.tunnels[i].Status.Conditions = []metav1.Condition{
						*g1Denied(metav1.ConditionFalse, "RefNotPermitted", `namespace "expl-gw-1" is not granted`),
					}
				}
			}
			journal := []cfstub.Call{f.tunnelCreate("tun-1"), f.tokenGet(idTun)}
			if call, blamed, violated := f.g1Check(t, journal, map[string]int{"tun-1": len(journal)}, len(journal)); violated {
				t.Fatalf("calls below the owner watermark must be excused; violated on %s %s blamed %q", call.Method, call.Path, blamed)
			}
			// A fresh call above the mark must still fail.
			journal = append(journal, f.tokenGet(idTun))
			if _, blamed, violated := f.g1Check(t, journal, map[string]int{"tun-1": len(journal) - 1}, len(journal)); !violated || blamed != "tun-1" {
				t.Fatalf("fresh call above the mark must fail blamed tun-1; violated=%v blamed=%q", violated, blamed)
			}
		})

		t.Run("unattributable calls below the shared watermark are excused", func(t *testing.T) {
			f := g1MachineFixture()
			f.liveTunnel("gw-1", "", nil)
			stray := cfstub.Call{Method: http.MethodPost, Path: "/zones/zone-1/dns_records",
				Body: `{"name":"app.expl1.example.com","content":"foreign.example.com"}`}
			if _, _, violated := f.g1Check(t, []cfstub.Call{stray}, nil, 1); violated {
				t.Fatal("unattributable call below the shared mark must be excused")
			}
		})

		t.Run("bound tunnel's own unauthorized calls still fail", func(t *testing.T) {
			f := g1MachineFixture()
			f.liveTunnel("gw-1", "", nil)
			journal := []cfstub.Call{f.tunnelCreate("gw-1")}
			if _, blamed, violated := f.g1Check(t, journal, nil, len(journal)); !violated || blamed != "gw-1" {
				t.Fatalf("bound tunnel's own provisioning must fail blamed gw-1; violated=%v blamed=%q", violated, blamed)
			}
		})
	})

	t.Run("single writer scoping", func(t *testing.T) {
		const idTun, idGw = "id-tun", "id-gw"

		t.Run("bound tunnel's own config PUT counts via status.tunnelId", func(t *testing.T) {
			f := g1MachineFixture()
			f.liveTunnel("gw-1", idGw, g1Accepted("Accepted"))
			if !f.attribution().boundConfigWrite(f.configPut(idGw)) {
				t.Fatal("bound tunnel's own config PUT must count")
			}
		})

		t.Run("sibling Direct config PUT does not count", func(t *testing.T) {
			f := g1MachineFixture()
			f.liveTunnel("gw-1", idGw, g1Accepted("Accepted"))
			f.liveTunnel("tun-1", idTun, g1Accepted("Accepted"))
			if f.attribution().boundConfigWrite(f.configPut(idTun)) {
				t.Fatal("sibling's config PUT must not count for the bound window")
			}
		})

		t.Run("bound config PUT resolves via stub name before status commit", func(t *testing.T) {
			f := g1MachineFixture()
			f.liveTunnel("gw-1", "", nil)
			f.remoteTunnel(idGw, "gw-1")
			if !f.attribution().boundConfigWrite(f.configPut(idGw)) {
				t.Fatal("bound config PUT must resolve through the stub name when status.tunnelId is empty")
			}
		})
	})
}
