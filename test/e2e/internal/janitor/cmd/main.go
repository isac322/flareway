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

// Package main runs the Flareway e2e janitor command.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/isac322/flareway/test/e2e/internal/cfapi"
	"github.com/isac322/flareway/test/e2e/internal/janitor"
	"github.com/isac322/flareway/test/e2e/internal/names"
)

func main() {
	olderThan := flag.Duration("older-than", 2*time.Hour, "minimum resource age eligible for deletion")
	prefix := flag.String("prefix", names.OwnerPrefix, "ownership prefix eligible for deletion")
	flag.Parse()

	token := os.Getenv("FLAREWAY_E2E_CF_API_TOKEN")
	accountID := os.Getenv("FLAREWAY_E2E_CF_ACCOUNT_ID")
	zoneName := os.Getenv("FLAREWAY_E2E_ZONE")
	if token == "" || accountID == "" || zoneName == "" {
		fmt.Fprintln(os.Stderr, "FLAREWAY_E2E_CF_API_TOKEN, FLAREWAY_E2E_CF_ACCOUNT_ID, and FLAREWAY_E2E_ZONE are required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	api := cfapi.New(token, accountID, os.Getenv("FLAREWAY_E2E_CF_BASE_URL"))
	if err := api.ResolveZone(ctx, zoneName); err != nil {
		cancel()
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	report, err := janitor.SweepPrefix(ctx, api, *prefix, *olderThan, time.Now().UTC())
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("deleted Access applications=%d policies=%d service tokens=%d DNS records=%d tunnels=%d; skipped connected tunnels=%d\n", report.AccessApplicationsDeleted, report.AccessPoliciesDeleted, report.ServiceTokensDeleted, report.DNSRecordsDeleted, report.TunnelsDeleted, report.ConnectedSkipped)
}
