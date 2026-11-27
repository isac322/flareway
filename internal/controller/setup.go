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

package controller

import (
	"fmt"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/sweep"
)

// ProductionControllerOptions configures the canonical controller registrations
// and sweep-topic subscriptions shared between cmd/main.go and envtest suites.
type ProductionControllerOptions struct {
	Groups            sweep.ControllerGroups
	Client            client.Client
	APIReader         client.Reader
	ClientFor         func(controllerKind string) (client.Client, client.Reader)
	CloudflareFactory flarecloudflare.ClientFactory
	AccountFactory    flarecloudflare.AccountClientFactory
	Snapshots         SnapshotPublisher
	OperatorNamespace string
	Prober            dataplane.Prober
	DriftPolicy       DriftPolicy
	Freshness         freshness.Policy
	Invalidator       *freshness.Latch
	Sweeper           *sweep.Sweeper
	XDSEvents         <-chan event.GenericEvent

	// SkipAccountController omits CloudflareAccountReconciler for harnesses
	// that seed CloudflareAccount status directly without an account fake.
	SkipAccountController bool

	// Optional per-controller Cloudflare client overrides used by envtests
	// that wire isolated per-kind fakes through the production setup path.
	GatewayCloudflareFactory       flarecloudflare.ClientFactory
	TunnelClient                   NewTunnelCloudflareClient
	PrivateNetworkClient           NewPrivateNetworkCloudflareClient
	WARPConnectorClient            NewWARPConnectorCloudflareClient
	AccessClient                   NewAccessCloudflareClient
	AccessGroupClient              NewAccessCloudflareClient
	IdentityProviderClient         NewAccessCloudflareClient
	DevicePostureRuleClient        NewAccessCloudflareClient
	ServiceTokenClient             NewAccessCloudflareClient
	AccessApplicationClient        NewAccessApplicationCloudflareClient
	AccessStandaloneClient         NewAccessCloudflareClient
	AccessInfrastructureClient     NewAccessCloudflareClient
	AccessCustomPageClient         NewAccessCloudflareClient
	DevicePostureIntegrationClient NewAccessCloudflareClient
	DeviceProfileClient            NewDeviceProfileCloudflareClient
	DeviceClient                   NewDeviceCloudflareClient
	OrganizationClient             NewOrganizationCloudflareClient
	GatewayClient                  NewGatewayCloudflareClient
}

// SetupProductionControllers registers all enabled Flareway controllers and
// binds their canonical per-kind sweep subscriptions onto mgr.
func SetupProductionControllers(mgr ctrl.Manager, opts ProductionControllerOptions) error {
	baseClient := opts.Client
	if baseClient == nil {
		baseClient = mgr.GetClient()
	}
	baseReader := opts.APIReader
	if baseReader == nil {
		baseReader = mgr.GetAPIReader()
	}
	operatorNamespace := opts.OperatorNamespace
	if operatorNamespace == "" {
		operatorNamespace = dataplane.DefaultOperatorNamespace
	}
	prober := opts.Prober
	if prober == nil {
		prober = dataplane.NewHTTPProber(5 * time.Second)
	}
	clientsFor := func(controllerKind string) (client.Client, client.Reader) {
		if opts.ClientFor == nil {
			return baseClient, baseReader
		}
		c, r := opts.ClientFor(controllerKind)
		if c == nil {
			c = baseClient
		}
		if r == nil {
			r = baseReader
		}
		return c, r
	}
	sweepEventsFor := func(kind string) <-chan event.GenericEvent {
		if opts.Sweeper == nil {
			return nil
		}
		return opts.Sweeper.EventsFor(kind)
	}

	if !opts.SkipAccountController &&
		(opts.Groups.Gateway || opts.Groups.Access || opts.Groups.PrivateNetwork || opts.Groups.Device || opts.Groups.Organization) {
		accountFactory := opts.AccountFactory
		if accountFactory == nil {
			if candidate, ok := opts.CloudflareFactory.(flarecloudflare.AccountClientFactory); ok {
				accountFactory = candidate
			}
		}
		c, _ := clientsFor("CloudflareAccount")
		if err := (&CloudflareAccountReconciler{
			Client:     c,
			Scheme:     mgr.GetScheme(),
			Cloudflare: accountFactory,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up CloudflareAccount controller: %w", err)
		}
	}

	if opts.Groups.Gateway {
		gwClassClient, _ := clientsFor("GatewayClass")
		if err := (&GatewayClassReconciler{
			Client: gwClassClient,
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up GatewayClass controller: %w", err)
		}

		gwFactory := opts.GatewayCloudflareFactory
		if gwFactory == nil {
			gwFactory = opts.CloudflareFactory
		}
		gwClient, gwReader := clientsFor("Gateway")
		if err := (&GatewayReconciler{
			Client:            gwClient,
			APIReader:         gwReader,
			Scheme:            mgr.GetScheme(),
			Snapshots:         opts.Snapshots,
			OperatorNamespace: operatorNamespace,
			CloudflareFactory: gwFactory,
			Prober:            prober,
			DriftPolicy:       opts.DriftPolicy,
			Freshness:         opts.Freshness,
			Invalidator:       opts.Invalidator,
			SweepEvents:       sweepEventsFor("CloudflareTunnel"),
			XDSEvents:         opts.XDSEvents,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up Gateway controller: %w", err)
		}

		tunnelNewClient := opts.TunnelClient
		if tunnelNewClient == nil {
			tunnelNewClient = TunnelClientFromFactory(opts.CloudflareFactory)
		}
		tunnelClient, tunnelReader := clientsFor("CloudflareTunnel")
		if err := (&CloudflareTunnelReconciler{
			Client:              tunnelClient,
			APIReader:           tunnelReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: tunnelNewClient,
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("CloudflareTunnel"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up CloudflareTunnel controller: %w", err)
		}
	}

	if opts.Groups.PrivateNetwork {
		pnNewClient := opts.PrivateNetworkClient
		if pnNewClient == nil {
			pnNewClient = PrivateNetworkClientFromFactory(opts.CloudflareFactory)
		}
		vnetClient, vnetReader := clientsFor("VirtualNetwork")
		if err := (&VirtualNetworkReconciler{
			Client:              vnetClient,
			APIReader:           vnetReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: pnNewClient,
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("VirtualNetwork"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up VirtualNetwork controller: %w", err)
		}
		nrClient, nrReader := clientsFor("NetworkRoute")
		if err := (&NetworkRouteReconciler{
			Client:              nrClient,
			APIReader:           nrReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: pnNewClient,
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("NetworkRoute"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up NetworkRoute controller: %w", err)
		}
		hrClient, hrReader := clientsFor("HostnameRoute")
		if err := (&HostnameRouteReconciler{
			Client:              hrClient,
			APIReader:           hrReader,
			Scheme:              mgr.GetScheme(),
			OperatorNamespace:   operatorNamespace,
			NewCloudflareClient: pnNewClient,
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("HostnameRoute"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up HostnameRoute controller: %w", err)
		}
		wcNewClient := opts.WARPConnectorClient
		if wcNewClient == nil {
			wcNewClient = WARPConnectorClientFromFactory(opts.CloudflareFactory)
		}
		wcClient, wcReader := clientsFor("WARPConnector")
		if err := (&WARPConnectorReconciler{
			Client:              wcClient,
			APIReader:           wcReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: wcNewClient,
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("WARPConnector"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up WARPConnector controller: %w", err)
		}
	}

	if opts.Groups.Access {
		defaultAccessClient := opts.AccessClient
		if defaultAccessClient == nil {
			defaultAccessClient = AccessClientFromFactory(opts.CloudflareFactory)
		}
		accessClientOr := func(override NewAccessCloudflareClient) NewAccessCloudflareClient {
			if override != nil {
				return override
			}
			return defaultAccessClient
		}

		polClient, polReader := clientsFor("AccessPolicy")
		if err := (&AccessPolicyReconciler{
			Client:              polClient,
			APIReader:           polReader,
			Scheme:              mgr.GetScheme(),
			Recorder:            mgr.GetEventRecorder("access-policy"),
			DriftPolicy:         opts.DriftPolicy,
			NewCloudflareClient: defaultAccessClient,
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("AccessPolicy"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up AccessPolicy controller: %w", err)
		}

		grpClient, grpReader := clientsFor("AccessGroup")
		if err := (&AccessGroupReconciler{
			Client:              grpClient,
			APIReader:           grpReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: accessClientOr(opts.AccessGroupClient),
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("AccessGroup"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up AccessGroup controller: %w", err)
		}

		idpClient, idpReader := clientsFor("IdentityProvider")
		if err := (&IdentityProviderReconciler{
			Client:              idpClient,
			APIReader:           idpReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: accessClientOr(opts.IdentityProviderClient),
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("IdentityProvider"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up IdentityProvider controller: %w", err)
		}

		dprClient, dprReader := clientsFor("DevicePostureRule")
		if err := (&DevicePostureRuleReconciler{
			Client:              dprClient,
			APIReader:           dprReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: accessClientOr(opts.DevicePostureRuleClient),
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("DevicePostureRule"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up DevicePostureRule controller: %w", err)
		}

		stClient, stReader := clientsFor("ServiceToken")
		if err := (&ServiceTokenReconciler{
			Client:              stClient,
			APIReader:           stReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: accessClientOr(opts.ServiceTokenClient),
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("ServiceToken"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up ServiceToken controller: %w", err)
		}

		appNewClient := opts.AccessApplicationClient
		if appNewClient == nil {
			appNewClient = AccessApplicationClientFromFactory(opts.CloudflareFactory)
		}
		appClient, appReader := clientsFor("AccessApplication")
		if err := (&AccessApplicationReconciler{
			Client:              appClient,
			APIReader:           appReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: appNewClient,
			OperatorNamespace:   operatorNamespace,
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("AccessApplication"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up AccessApplication controller: %w", err)
		}

		saClient, saReader := clientsFor("AccessStandaloneApplication")
		if err := (&AccessStandaloneApplicationReconciler{
			Client:              saClient,
			APIReader:           saReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: accessClientOr(opts.AccessStandaloneClient),
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("AccessStandaloneApplication"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up AccessStandaloneApplication controller: %w", err)
		}

		infraClient, infraReader := clientsFor("AccessInfrastructureTarget")
		if err := (&AccessInfrastructureTargetReconciler{
			Client:              infraClient,
			APIReader:           infraReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: accessClientOr(opts.AccessInfrastructureClient),
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("AccessInfrastructureTarget"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up AccessInfrastructureTarget controller: %w", err)
		}

		cpClient, cpReader := clientsFor("AccessCustomPage")
		if err := (&AccessCustomPageReconciler{
			Client:              cpClient,
			APIReader:           cpReader,
			Scheme:              mgr.GetScheme(),
			Recorder:            mgr.GetEventRecorder("access-custom-page"),
			NewCloudflareClient: accessClientOr(opts.AccessCustomPageClient),
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("AccessCustomPage"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up AccessCustomPage controller: %w", err)
		}

		dpiClient, dpiReader := clientsFor("DevicePostureIntegration")
		if err := (&DevicePostureIntegrationReconciler{
			Client:              dpiClient,
			APIReader:           dpiReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: accessClientOr(opts.DevicePostureIntegrationClient),
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("DevicePostureIntegration"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up DevicePostureIntegration controller: %w", err)
		}
	}

	if opts.Groups.Device {
		dpNewClient := opts.DeviceProfileClient
		if dpNewClient == nil {
			dpNewClient = DeviceProfileClientFromFactory(opts.CloudflareFactory)
		}
		dpClient, dpReader := clientsFor("DeviceProfile")
		if err := (&DeviceProfileReconciler{
			Client:              dpClient,
			APIReader:           dpReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: dpNewClient,
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("DeviceProfile"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up DeviceProfile controller: %w", err)
		}

		dsNewClient := opts.DeviceClient
		if dsNewClient == nil {
			dsNewClient = DeviceClientFromFactory(opts.CloudflareFactory)
		}
		dsClient, dsReader := clientsFor("DeviceSettings")
		if err := (&DeviceSettingsReconciler{
			Client:              dsClient,
			APIReader:           dsReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: dsNewClient,
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up DeviceSettings controller: %w", err)
		}
	}

	if opts.Groups.Organization {
		orgNewClient := opts.OrganizationClient
		if orgNewClient == nil {
			orgNewClient = OrganizationClientFromFactory(opts.CloudflareFactory)
		}
		orgClient, orgReader := clientsFor("ZeroTrustOrganization")
		if err := (&ZeroTrustOrganizationReconciler{
			Client:              orgClient,
			APIReader:           orgReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: orgNewClient,
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up ZeroTrustOrganization controller: %w", err)
		}

		gwNewClient := opts.GatewayClient
		if gwNewClient == nil {
			gwNewClient = GatewayClientFromFactory(opts.CloudflareFactory)
		}
		ztlClient, ztlReader := clientsFor("ZeroTrustList")
		if err := (&ZeroTrustListReconciler{
			Client:              ztlClient,
			APIReader:           ztlReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: gwNewClient,
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("ZeroTrustList"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up ZeroTrustList controller: %w", err)
		}

		gwPolClient, gwPolReader := clientsFor("ZeroTrustGatewayPolicy")
		if err := (&ZeroTrustGatewayPolicyReconciler{
			Client:              gwPolClient,
			APIReader:           gwPolReader,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: gwNewClient,
			Freshness:           opts.Freshness,
			Invalidator:         opts.Invalidator,
			SweepEvents:         sweepEventsFor("ZeroTrustGatewayPolicy"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up ZeroTrustGatewayPolicy controller: %w", err)
		}
	}

	return nil
}
