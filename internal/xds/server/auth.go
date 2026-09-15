/*
Copyright 2026 The Flareway Authors.

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

package server

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const spiffePrefix = "spiffe://flareway.bhyoo.com/ns/"

// AuthorizeCertificate verifies that cert contains the sole SPIFFE URI allowed
// to claim nodeCluster. nodeCluster must be exactly "namespace/gateway".
func AuthorizeCertificate(cert *x509.Certificate, nodeCluster string) error {
	parts := strings.Split(nodeCluster, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || parts[0] == "." || parts[1] == "." || parts[0] == ".." || parts[1] == ".." {
		return fmt.Errorf("invalid node.cluster %q", nodeCluster)
	}
	if cert == nil {
		return errors.New("client certificate is missing")
	}
	want := spiffePrefix + parts[0] + "/gateway/" + parts[1]
	for _, uri := range cert.URIs {
		if uri != nil && uri.String() == want {
			return nil
		}
	}
	return fmt.Errorf("client certificate is not authorized for node.cluster %q", nodeCluster)
}

func sanAuthorizationInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		wrapped, err := newAuthorizedStream(stream)
		if err != nil {
			return status.Error(codes.PermissionDenied, err.Error())
		}
		return handler(srv, wrapped)
	}
}

type authorizedStream struct {
	grpc.ServerStream
	certificate *x509.Certificate
	cluster     string
	authorized  bool
}

func newAuthorizedStream(stream grpc.ServerStream) (*authorizedStream, error) {
	peerInfo, ok := peer.FromContext(stream.Context())
	if !ok || peerInfo.AuthInfo == nil {
		return nil, errors.New("mTLS peer information is missing")
	}
	tlsInfo, ok := peerInfo.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errors.New("peer did not use TLS")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nil, errors.New("verified client certificate is missing")
	}
	return &authorizedStream{
		ServerStream: stream,
		certificate:  tlsInfo.State.VerifiedChains[0][0],
	}, nil
}

func (s *authorizedStream) RecvMsg(message any) error {
	if err := s.ServerStream.RecvMsg(message); err != nil {
		return err
	}
	req, ok := message.(*discoveryv3.DeltaDiscoveryRequest)
	if !ok {
		return status.Error(codes.PermissionDenied, "only Delta ADS requests are authorized")
	}
	if !s.authorized {
		cluster := req.GetNode().GetCluster()
		if err := AuthorizeCertificate(s.certificate, cluster); err != nil {
			return status.Error(codes.PermissionDenied, err.Error())
		}
		s.cluster = cluster
		s.authorized = true
		return nil
	}
	if req.GetNode() != nil && req.GetNode().GetCluster() != "" && req.GetNode().GetCluster() != s.cluster {
		return status.Errorf(codes.PermissionDenied, "node.cluster changed from %q to %q", s.cluster, req.GetNode().GetCluster())
	}
	return nil
}
