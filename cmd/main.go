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

// Package main starts the Flareway controller manager.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlrecorder "sigs.k8s.io/controller-runtime/pkg/recorder"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
	"github.com/isac322/flareway/internal/controller"
	"github.com/isac322/flareway/internal/dataplane"
	"github.com/isac322/flareway/internal/freshness"
	"github.com/isac322/flareway/internal/observability"
	"github.com/isac322/flareway/internal/sweep"
	"github.com/isac322/flareway/internal/xds/pki"
	xdsserver "github.com/isac322/flareway/internal/xds/server"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

type eventRecorderAdapter struct {
	recorder ctrlrecorder.EventRecorder
}

func (adapter eventRecorderAdapter) Event(object runtime.Object, eventType, reason, message string) {
	adapter.recorder.Eventf(object, nil, eventType, reason, reason, "%s", message)
}

func (adapter eventRecorderAdapter) Eventf(object runtime.Object, eventType, reason, message string, args ...any) {
	adapter.recorder.Eventf(object, nil, eventType, reason, reason, message, args...)
}

func (adapter eventRecorderAdapter) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventType, reason, message string, args ...any) {
	adapter.recorder.AnnotatedEventf(object, nil, annotations, eventType, reason, reason, message, args...)
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.Install(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var webhookPort int
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var xdsAddr string
	var enableGatewayControllers bool
	var enableAccessControllers bool
	var enablePrivateNetworkControllers bool
	var enableDeviceControllers bool
	var enableOrganizationControllers bool
	var driftPolicyFlag string
	var freshnessAuthz, freshnessTraffic, freshnessIndirect, freshnessDisplay time.Duration
	var disableSweep bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for the controller manager and xDS server.")
	flag.StringVar(&xdsAddr, "xds-bind-address", xdsserver.DefaultAddress, "The address the Delta ADS and SDS server binds to.")
	flag.BoolVar(&enableGatewayControllers, "enable-gateway-controllers", true,
		"Enable GatewayClass, Gateway, and CloudflareTunnel controllers. The shared CloudflareAccount controller runs while any controller group is enabled.")
	flag.BoolVar(&enableAccessControllers, "enable-access-controllers", true,
		"Enable AccessApplication, AccessStandaloneApplication, AccessInfrastructureTarget, AccessCustomPage, AccessPolicy, AccessGroup, IdentityProvider, DevicePostureRule, DevicePostureIntegration, and ServiceToken controllers.")
	flag.BoolVar(&enablePrivateNetworkControllers, "enable-private-network-controllers", true,
		"Enable VirtualNetwork, NetworkRoute, HostnameRoute, and WARPConnector controllers.")
	flag.BoolVar(&enableDeviceControllers, "enable-device-controllers", true,
		"Enable DeviceProfile and DeviceSettings controllers.")
	flag.BoolVar(&enableOrganizationControllers, "enable-organization-controllers", true,
		"Enable ZeroTrustOrganization, ZeroTrustGatewayPolicy, and ZeroTrustList controllers.")
	flag.StringVar(&driftPolicyFlag, "drift-policy", string(controller.DriftPolicyOverwrite),
		"How reconcilers react to out-of-band drift on remote Cloudflare resources: Overwrite restores the desired state, Hold skips remote writes until manual intervention.")
	flag.DurationVar(&freshnessAuthz, "freshness-authz", 60*time.Second,
		"Freshness TTL for T1 (Authz) resources: IdentityProvider, ServiceToken, AccessGroup. A converged object skips remote reads until this TTL expires or drift invalidates it.")
	flag.DurationVar(&freshnessTraffic, "freshness-traffic", 300*time.Second,
		"Freshness TTL for T2 (Traffic) resources: VirtualNetwork, NetworkRoute, HostnameRoute, ZeroTrustGatewayPolicy, ZeroTrustList.")
	flag.DurationVar(&freshnessIndirect, "freshness-indirect", 1800*time.Second,
		"Freshness TTL for T3 (Indirect) resources: DeviceProfile, DeviceSettings, DevicePostureRule, DevicePostureIntegration, ZeroTrustOrganization, WARPConnector.")
	flag.DurationVar(&freshnessDisplay, "freshness-display", 0,
		"Freshness TTL for T4 (Display) resources. 0 disables periodic display reads.")
	flag.BoolVar(&disableSweep, "disable-sweep", false,
		"Disable the periodic drift sweep worker. Out-of-band drift is then detected only by freshness TTL expiry; use this to roll back the sweep if it misbehaves.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.IntVar(&webhookPort, "webhook-port", 9443, "Port the webhook server listens on. "+
		"Defaults to 9443. Set -1 to disable the webhook server.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	driftPolicy, err := controller.ParseDriftPolicy(driftPolicyFlag)
	if err != nil {
		setupLog.Error(err, "Invalid --drift-policy")
		os.Exit(1)
	}
	freshnessPolicy := freshness.Policy{
		Authz:    freshnessAuthz,
		Traffic:  freshnessTraffic,
		Indirect: freshnessIndirect,
		Display:  freshnessDisplay,
	}
	if err := freshnessPolicy.Validate(); err != nil {
		setupLog.Error(err, "Invalid --freshness-* flags")
		os.Exit(1)
	}

	gateLatch := freshness.NewLatch()
	var sweepEvents <-chan event.GenericEvent

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
		Port:    webhookPort,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.25.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.25.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       metricsServerOptions,
		WebhookServer:                 webhookServer,
		HealthProbeBindAddress:        probeAddr,
		LeaderElection:                enableLeaderElection,
		LeaderElectionID:              "flareway.bhyoo.com",
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}
	cloudflareFactory := flarecloudflare.NewFactory(ctrl.Log.WithName("cloudflare"))
	observedClient := observability.NewEventingClient(mgr.GetClient(), mgr.GetAPIReader(), eventRecorderAdapter{recorder: mgr.GetEventRecorder("flareway")})
	if enableGatewayControllers || enableAccessControllers || enablePrivateNetworkControllers || enableDeviceControllers || enableOrganizationControllers {
		if !disableSweep {
			sweeper := sweep.NewSweeper(sweep.SweeperOptions{
				Client:            mgr.GetClient(),
				APIReader:         mgr.GetAPIReader(),
				Scheme:            mgr.GetScheme(),
				CloudflareFactory: cloudflareFactory,
				Invalidator:       gateLatch,
				Policy:            freshnessPolicy,
				Logger:            ctrl.Log.WithName("sweep"),
				OperatorNamespace: dataplane.DefaultOperatorNamespace,
			})
			if err := mgr.Add(sweeper); err != nil {
				setupLog.Error(err, "Failed to register drift sweeper")
				os.Exit(1)
			}
			sweepEvents = sweeper.Events()
		}
		if err := (&controller.CloudflareAccountReconciler{
			Client:     observedClient,
			Scheme:     mgr.GetScheme(),
			Cloudflare: cloudflareFactory,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up CloudflareAccount controller")
			os.Exit(1)
		}
	}

	if enableGatewayControllers {
		bootstrapClient, err := client.New(mgr.GetConfig(), client.Options{Scheme: scheme})
		if err != nil {
			setupLog.Error(err, "Failed to create startup Kubernetes client")
			os.Exit(1)
		}
		caSecret, err := pki.EnsureCA(context.Background(), bootstrapClient)
		if err != nil {
			setupLog.Error(err, "Failed to ensure the xDS certificate authority")
			os.Exit(1)
		}
		xdsTLSConfig, err := pki.ServerTLSConfig(caSecret)
		if err != nil {
			setupLog.Error(err, "Failed to configure xDS mTLS")
			os.Exit(1)
		}
		xdsServer, err := xdsserver.New(xdsserver.Options{
			Address:   xdsAddr,
			TLSConfig: xdsTLSConfig,
			Logger:    ctrl.Log.WithName("xds"),
		})
		if err != nil {
			setupLog.Error(err, "Failed to construct xDS server")
			os.Exit(1)
		}
		if err := mgr.Add(xdsServer); err != nil {
			setupLog.Error(err, "Failed to register xDS server")
			os.Exit(1)
		}

		if err := (&controller.GatewayClassReconciler{
			Client: observedClient,
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up GatewayClass controller")
			os.Exit(1)
		}
		if err := (&controller.GatewayReconciler{
			Client:            observedClient,
			Scheme:            mgr.GetScheme(),
			Snapshots:         xdsServer,
			OperatorNamespace: dataplane.DefaultOperatorNamespace,
			CloudflareFactory: cloudflareFactory,
			Prober:            dataplane.NewHTTPProber(5 * time.Second),
			DriftPolicy:       driftPolicy,
			Freshness:         freshnessPolicy,
			Invalidator:       gateLatch,
			SweepEvents:       sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up Gateway controller")
			os.Exit(1)
		}
		if err := (&controller.CloudflareTunnelReconciler{
			Client:              observedClient,
			APIReader:           mgr.GetAPIReader(),
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.TunnelClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up CloudflareTunnel controller")
			os.Exit(1)
		}
	}
	if enablePrivateNetworkControllers {
		if err := (&controller.VirtualNetworkReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.PrivateNetworkClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up VirtualNetwork controller")
			os.Exit(1)
		}
		if err := (&controller.NetworkRouteReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.PrivateNetworkClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up NetworkRoute controller")
			os.Exit(1)
		}
		if err := (&controller.HostnameRouteReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			OperatorNamespace:   dataplane.DefaultOperatorNamespace,
			NewCloudflareClient: controller.PrivateNetworkClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up HostnameRoute controller")
			os.Exit(1)
		}
		if err := (&controller.WARPConnectorReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.WARPConnectorClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up WARPConnector controller")
			os.Exit(1)
		}
	}
	if enableAccessControllers {
		if err := (&controller.AccessPolicyReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			Recorder:            mgr.GetEventRecorder("access-policy"),
			DriftPolicy:         driftPolicy,
			NewCloudflareClient: controller.AccessClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up AccessPolicy controller")
			os.Exit(1)
		}
		if err := (&controller.AccessGroupReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.AccessClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up AccessGroup controller")
			os.Exit(1)
		}
		if err := (&controller.IdentityProviderReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.AccessClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up IdentityProvider controller")
			os.Exit(1)
		}
		if err := (&controller.DevicePostureRuleReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.AccessClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up DevicePostureRule controller")
			os.Exit(1)
		}
		if err := (&controller.ServiceTokenReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.AccessClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up ServiceToken controller")
			os.Exit(1)
		}
		if err := (&controller.AccessApplicationReconciler{
			Client:              observedClient,
			APIReader:           mgr.GetAPIReader(),
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.AccessApplicationClientFromFactory(cloudflareFactory),
			OperatorNamespace:   dataplane.DefaultOperatorNamespace,
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up AccessApplication controller")
			os.Exit(1)
		}
		if err := (&controller.AccessStandaloneApplicationReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.AccessClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up AccessStandaloneApplication controller")
			os.Exit(1)
		}
		if err := (&controller.AccessInfrastructureTargetReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.AccessClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up AccessInfrastructureTarget controller")
			os.Exit(1)
		}
		if err := (&controller.AccessCustomPageReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			Recorder:            mgr.GetEventRecorder("access-custom-page"),
			NewCloudflareClient: controller.AccessClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up AccessCustomPage controller")
			os.Exit(1)
		}
		if err := (&controller.DevicePostureIntegrationReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.AccessClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up DevicePostureIntegration controller")
			os.Exit(1)
		}
	}
	if enableDeviceControllers {
		if err := (&controller.DeviceProfileReconciler{
			Client:              observedClient,
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.DeviceProfileClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up DeviceProfile controller")
			os.Exit(1)
		}
		if err := (&controller.DeviceSettingsReconciler{
			Client:              observedClient,
			APIReader:           mgr.GetAPIReader(),
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.DeviceClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up DeviceSettings controller")
			os.Exit(1)
		}
	}
	if enableOrganizationControllers {
		if err := (&controller.ZeroTrustOrganizationReconciler{
			Client:              observedClient,
			APIReader:           mgr.GetAPIReader(),
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.OrganizationClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up ZeroTrustOrganization controller")
			os.Exit(1)
		}
		if err := (&controller.ZeroTrustListReconciler{
			Client:              observedClient,
			APIReader:           mgr.GetAPIReader(),
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.GatewayClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up ZeroTrustList controller")
			os.Exit(1)
		}
		if err := (&controller.ZeroTrustGatewayPolicyReconciler{
			Client:              observedClient,
			APIReader:           mgr.GetAPIReader(),
			Scheme:              mgr.GetScheme(),
			NewCloudflareClient: controller.GatewayClientFromFactory(cloudflareFactory),
			Freshness:           freshnessPolicy,
			Invalidator:         gateLatch,
			SweepEvents:         sweepEvents,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to set up ZeroTrustGatewayPolicy controller")
			os.Exit(1)
		}
	}

	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}
