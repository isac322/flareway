package server

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestSnapshotRequiredTypesUsesActualSDSReference(t *testing.T) {
	tlsConfig, err := anypb.New(&tlsv3.DownstreamTlsContext{CommonTlsContext: &tlsv3.CommonTlsContext{TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{{Name: "referenced-cert"}}}})
	if err != nil {
		t.Fatal(err)
	}
	listener := &listenerv3.Listener{Name: "listener", FilterChains: []*listenerv3.FilterChain{{TransportSocket: &corev3.TransportSocket{Name: "tls", ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: tlsConfig}}}}}
	resources := map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ListenerType: {listener},
		resourcev3.SecretType:   {&tlsv3.Secret{Name: "referenced-cert"}, &tlsv3.Secret{Name: "unreferenced-cert"}},
	}
	snapshot, err := cachev3.NewSnapshot("v1", resources)
	if err != nil {
		t.Fatal(err)
	}
	required := snapshotRequiredTypes(snapshot)
	if _, ok := required[string(resourcev3.SecretType)]; !ok {
		t.Fatal("actual SDS-referenced Secret type was not required")
	}

	resources[resourcev3.SecretType] = []cachetypes.Resource{&tlsv3.Secret{Name: "unreferenced-cert"}}
	snapshot, err = cachev3.NewSnapshot("v2", resources)
	if err != nil {
		t.Fatal(err)
	}
	required = snapshotRequiredTypes(snapshot)
	if _, ok := required[string(resourcev3.SecretType)]; ok {
		t.Fatal("unreferenced Secret type incorrectly became required")
	}
}
