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

package cfstub

import "time"

// AccessServiceTokenCredentials exposes credential transition state to tests;
// service-token HTTP list and get responses remain secret-free.
type AccessServiceTokenCredentials struct {
	ClientID                      string
	ClientSecret                  string
	PreviousClientSecret          string
	PreviousClientSecretExpiresAt string // Canonical RFC3339 value received on the wire.
}

// ServiceTokenCredentials returns the current and grace-period credentials for
// one account- or zone-scoped token. Scope is "accounts/<id>" or "zones/<id>".
func (s *State) ServiceTokenCredentials(scope, tokenID string) (AccessServiceTokenCredentials, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	token, found := s.serviceTokens[scope][tokenID]
	if !found {
		return AccessServiceTokenCredentials{}, false
	}
	credentials := AccessServiceTokenCredentials{
		ClientID:             token.ClientID,
		ClientSecret:         token.clientSecret,
		PreviousClientSecret: token.previousClientSecret,
	}
	if token.previousClientSecretExpiresAt != nil {
		credentials.PreviousClientSecretExpiresAt = token.previousClientSecretExpiresAt.Format(time.RFC3339)
	}
	return credentials, true
}
