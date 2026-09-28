// Every user-visible string on the landing page (src/pages/index.astro) lives
// here so the copy deck can be replaced without touching components.
//
// Conventions:
// - Fields named `html` (or ending in `Html`) are trusted inline markup rendered
//   with `set:html`: use only <code>, <sup>, <em>, <strong>, and <a>.
// - Every other field is plain text and is escaped.
// - Every claim must trace to the repository (README.md, config/samples/,
//   conformance/reports/v1.6.2/flareway/). ™/® marks go on first use only.
// - `lines` on demo outputs reference YAML lines as `<file>:<from>-<to>` where
//   file is `g` (gateway_v1_gateway.yaml) or `r` (gateway_v1_httproute.yaml).

export interface Link {
	label: string;
	href: string;
}

export interface LandingCopy {
	meta: {
		title: string;
		description: string;
		ogTitle: string;
		siteName: string;
	};
	header: {
		homeLabel: string;
		tabsLabel: string;
		githubLabel: string;
		starLabel: string;
		/** Accessible name of the GitHub button; `{count}` is replaced when a count exists. */
		githubAria: string;
		githubAriaCount: string;
	};
	hero: {
		lockupLabel: string;
		plateNote: string;
		chartOpened: string;
		chartNoInbound: string;
		titleHtml: string;
		ledeHtml: string;
		primary: Link;
		secondary: Link;
		tertiaryHtml: string;
		tertiaryHref: string;
		proofLabel: string;
		proof: { value: string; label: string; href: string }[];
	};
	why: {
		heading: string;
		ledeHtml: string;
		alone: { captionHtml: string; items: string[]; note: string };
		with: { captionHtml: string; items: { feature: string; gloss: string }[]; noteHtml: string };
	};
	how: {
		heading: string;
		ledeHtml: string;
		figure: {
			title: string;
			desc: string;
			browsers: string;
			browsersSub: string;
			warp: string;
			warpSub: string;
			edge: string;
			edgeSub1: string;
			edgeSub2: string;
			edgeHost: string;
			noInbound: string;
			tunnel: string;
			tunnelProto: string;
			boundary: string;
			boundarySub: string;
			opened: string;
			podLabel: string;
			cloudflared: string;
			envoy: string;
			loopback: string;
			coredns: string;
			controllerName: string;
			controllerSub: string;
			xds: string;
			routed: string;
			service: string;
			pods: string;
			caption: string;
			ratio: string;
		};
	};
	demo: {
		heading: string;
		ledeHtml: string;
		copy: string;
		copied: string;
		copyFailed: string;
		outputsHeading: string;
		outputs: { lines: string; titleHtml: string; bodyHtml: string }[];
		noteHtml: string;
	};
	access: {
		heading: string;
		ledeHtml: string;
		policy: { heading: string; bodyHtml: string; variantsCaption: string; variants: { name: string; gloss: string }[] };
		warp: { heading: string; bodyHtml: string; kinds: string[]; kindsNoteHtml: string };
		direct: { heading: string; bodyHtml: string; origins: string[] };
		more: Link;
	};
	failClosed: {
		heading: string;
		ledeHtml: string;
		gates: { title: string; bodyHtml: string }[];
		guarantees: { titleHtml: string; bodyHtml: string }[];
		more: Link;
	};
	tryIt: {
		heading: string;
		ledeHtml: string;
		command: string;
		commandCaption: string;
		copy: string;
		copied: string;
		copyFailed: string;
		printsHeading: string;
		printsHtml: string[];
		notesHtml: string[];
		primary: Link;
		secondary: Link;
	};
	star: {
		heading: string;
		bodyHtml: string;
		cta: string;
		ctaCount: string;
		secondary: Link;
	};
	footer: {
		navLabel: string;
		tagline: string;
		groups: { heading: string; links: Link[] }[];
		top: string;
	};
}

export const landingCopy: LandingCopy = {
	meta: {
		title: 'Flareway — Kubernetes Gateway API for Cloudflare Tunnel',
		description:
			'A Kubernetes operator implementing the Gateway API for Cloudflare Tunnel: each Gateway becomes a tunnel, and HTTPRoute rules become Envoy routes.',
		ogTitle: 'Flareway — a Gateway that becomes a Cloudflare Tunnel',
		siteName: 'Flareway',
	},

	header: {
		homeLabel: 'Flareway home',
		tabsLabel: 'Site sections',
		githubLabel: 'GitHub',
		starLabel: 'Star',
		githubAria: 'Star Flareway on GitHub',
		githubAriaCount: 'Star Flareway on GitHub ({count} stars)',
	},

	hero: {
		lockupLabel: 'flareway',
		plateNote: 'a lit way through the cloud',
		chartOpened: 'opened from inside',
		chartNoInbound: 'no inbound',
		titleHtml: 'A <code>Gateway</code> that becomes a Cloudflare Tunnel<sup>™</sup>.',
		ledeHtml:
			'<code>Gateway</code> and <code>HTTPRoute</code> become a managed Cloudflare Tunnel and Envoy routing — Access and WARP<sup>®</sup> are CRDs too. One outbound connection, nothing inbound.',
		primary: { label: 'Get started', href: '/docs/operations/install/' },
		secondary: { label: 'GitHub', href: 'https://github.com/isac322/flareway' },
		tertiaryHtml: 'Try <code>helm template</code> — no cluster, no credentials',
		tertiaryHref: '#try',
		proofLabel: 'Project facts',
		proof: [
			{
				value: 'Core 37/37',
				label: 'Gateway API conformance, local dev run',
				href: '/docs/conformance/gateway-api-v1-6-2/',
			},
			{ value: '22 CRDs', label: 'flareway.bhyoo.com/v1alpha1', href: '/docs/reference/api/' },
			{
				value: 'Apache-2.0',
				label: 'open source',
				href: 'https://github.com/isac322/flareway/blob/main/LICENSE',
			},
		],
	},

	why: {
		heading: 'A tunnel is transport. Routing needs a proxy.',
		ledeHtml:
			'Cloudflare Tunnel makes a cluster reachable with no inbound ports or public IPs. But <code>cloudflared</code> alone matches only hostnames and simple paths.',
		alone: {
			captionHtml: '<code>cloudflared</code> ingress rules',
			items: ['hostname', 'simple path'],
			note: 'No method, query, or header matches. No weighted splits.',
		},
		with: {
			captionHtml: '<code>HTTPRoute</code> through Flareway’s in-pod Envoy',
			items: [
				{ feature: 'HTTPRouteMethodMatching', gloss: 'match on HTTP method' },
				{ feature: 'HTTPRouteQueryParamMatching', gloss: 'match on query parameters' },
				{ feature: 'HTTPRoutePathRewrite', gloss: 'rewrite the path' },
				{ feature: 'HTTPRouteHostRewrite', gloss: 'rewrite the host' },
				{ feature: 'HTTPRoutePathRedirect', gloss: 'redirects, with 303/307/308' },
				{ feature: 'HTTPRouteRequestMirror', gloss: 'mirror requests, including by percentage' },
				{ feature: 'HTTPRouteRequestTimeout', gloss: 'request and backend timeouts' },
				{ feature: 'HTTPRouteBackendProtocolWebSocket', gloss: 'WebSocket and h2c backends' },
				{ feature: 'BackendTLSPolicy', gloss: 'TLS to backends, with SAN validation' },
			],
			noteHtml:
				'Header matches and weighted backends are Gateway API Core. Every Extended feature listed passed the local <a href="/docs/conformance/gateway-api-v1-6-2/">conformance run</a>.',
		},
	},

	how: {
		heading: 'One Gateway, one tunnel, one data-plane pod.',
		ledeHtml:
			'Traffic enters only through <code>cloudflared</code>, which dials out over QUIC/HTTP2. Envoy takes decrypted requests over loopback and applies the routes the controller streams to it over xDS.',
		figure: {
			title: 'How traffic reaches the cluster',
			desc: 'Browsers and WARP devices reach the Cloudflare edge. Inbound paths into the cluster are blocked at a sealed boundary. One outbound tunnel, opened by cloudflared inside the data-plane pod, crosses the boundary. cloudflared hands requests to Envoy over loopback; the Flareway controller streams routes to Envoy over xDS. Envoy forwards to Services and Pods.',
			browsers: 'Browsers',
			browsersSub: 'public hostnames',
			warp: 'WARP devices',
			warpSub: 'private network routes',
			edge: 'Cloudflare® edge',
			edgeSub1: 'edge TLS · proxied CNAME',
			edgeSub2: 'private network route',
			edgeHost: '<tunnel-id>.cfargotunnel.com',
			noInbound: 'no inbound',
			tunnel: 'one outbound tunnel',
			tunnelProto: 'QUIC / HTTP2',
			boundary: 'sealed cluster boundary',
			boundarySub: 'no inbound ports, no public IPs',
			opened: 'opened from inside',
			podLabel: 'data-plane pod',
			cloudflared: 'cloudflared',
			envoy: 'Envoy',
			loopback: 'loopback',
			coredns: '+ CoreDNS sidecar for private listeners',
			controllerName: 'flareway',
			controllerSub: 'controller',
			xds: 'xDS · Delta ADS',
			routed: 'routed by your HTTPRoute rules',
			service: 'Service',
			pods: 'Pods',
			caption: 'Traffic rides a tunnel the cluster opens outbound. Nothing listens inbound.',
			ratio: '1 Gateway : 1 tunnel : 1 data plane',
		},
	},

	demo: {
		heading: 'Two standard objects in. Five results out.',
		ledeHtml:
			'The sample manifests from <code>config/samples</code>, unedited. No annotations: the tunnel hangs off the standard <code>parametersRef</code>. Hover or focus a result to see the lines behind it.',
		copy: 'Copy',
		copied: 'Copied',
		copyFailed: 'Select to copy',
		outputsHeading: 'What the controller produces',
		outputs: [
			{
				lines: 'g:2,7-12',
				titleHtml: 'A Cloudflare Tunnel, from <code>CloudflareTunnel/public</code>',
				bodyHtml: 'One tunnel per <code>Gateway</code>, owned by the CRD you referenced — never adopted by name alone.',
			},
			{
				lines: 'g:1-2,7',
				titleHtml: 'A data-plane Deployment',
				bodyHtml:
					'One per <code>Gateway</code>: a pod running <code>cloudflared</code> and Envoy, plus a CoreDNS sidecar when the Gateway has private listeners.',
			},
			{
				lines: 'g:14-17;r:10-11',
				titleHtml: 'A proxied DNS record',
				bodyHtml:
					'<code>app.example.com</code> → CNAME to the tunnel hostname, ownership marked in the record comment. Cloudflare owns edge TLS.',
			},
			{
				lines: 'r:7-9,12-19',
				titleHtml: 'Envoy routes over xDS',
				bodyHtml:
					'The controller streams <code>PathPrefix /</code> → <code>example-service:8080</code> to Envoy (Delta ADS). Method, header, and query matches, plus weighted backends, ride the same xDS stream.',
			},
			{
				lines: 'g:1-5',
				titleHtml: 'A <code>Programmed</code> Gateway, when it’s true',
				bodyHtml:
					'Reported only after edge DNS, tunnel sessions, xDS configuration, and the Envoy data plane have all converged.',
			},
		],
		noteHtml:
			'Access policies attach to routes through GEP-713 policy attachment — next section. More in the <a href="https://github.com/isac322/flareway/tree/main/config/samples">sample manifests</a>.',
	},

	access: {
		heading: 'Access policies live next to the routes they protect.',
		ledeHtml:
			'Attach a Cloudflare Access<sup>™</sup> policy, not an annotation. Reach private services over WARP, managed as Kubernetes<sup>®</sup> resources.',
		policy: {
			heading: 'Policy attachment (GEP-713)',
			bodyHtml:
				'An <code>AccessApplication</code> targets a <code>Gateway</code> or an <code>HTTPRoute</code>, optionally scoped to a path prefix. Envoy’s <code>jwt_authn</code> filter verifies <code>Cf-Access-Jwt-Assertion</code> against the Cloudflare JWKS endpoint. Routes without an attachment carry no JWT filter.',
			variantsCaption: '<code>AccessApplication</code> types',
			variants: [
				{ name: 'SelfHosted', gloss: 'web applications' },
				{ name: 'SSH', gloss: 'browser SSH' },
				{ name: 'VNC', gloss: 'browser VNC' },
				{ name: 'RDP', gloss: 'browser RDP' },
				{ name: 'MCP', gloss: 'MCP servers' },
				{ name: 'ProxyEndpoint', gloss: 'identity proxy' },
			],
		},
		warp: {
			heading: 'Private networking over WARP',
			bodyHtml:
				'Private listeners terminate TLS in Envoy with a certificate Secret you supply. WARP clients reach them through Cloudflare private network routes; a CoreDNS sidecar answers private hostnames with 127.0.0.1 so that traffic also passes through Envoy.',
			kinds: ['VirtualNetwork', 'NetworkRoute', 'HostnameRoute', 'WARPConnector'],
			kindsNoteHtml: 'for WARP reachability and k8s-to-VPC site-to-site links',
		},
		direct: {
			heading: 'Direct mode for non-Gateway origins',
			bodyHtml:
				'A <code>CloudflareTunnel</code> in Direct mode owns the complete remote <code>cloudflared</code> configuration.',
			origins: ['TCP', 'SSH', 'RDP', 'bastion'],
		},
		more: { label: 'Read the API reference', href: '/docs/reference/api/' },
	},

	failClosed: {
		heading: 'Fail closed, on purpose',
		ledeHtml: 'On uncertainty, Flareway denies. Every operation needs a yes from two authorization layers.',
		gates: [
			{
				title: 'Kubernetes RBAC',
				bodyHtml: 'What the controller itself may read and write in the cluster.',
			},
			{
				title: 'CloudflareAccount grants',
				bodyHtml:
					'<code>spec.grants</code> scopes which namespaces, hostnames, zones, and exposures may use an account. A namespace that matches no grant is denied.',
			},
		],
		guarantees: [
			{
				titleHtml: 'Adoption is explicit',
				bodyHtml: 'Existing remote objects are taken over only through <code>AdoptById</code> — never by name alone.',
			},
			{
				titleHtml: 'Deletion never opens a route',
				bodyHtml: 'Deleting an <code>AccessApplication</code> never makes a protected route public.',
			},
			{
				titleHtml: 'Credentials stay in Secrets',
				bodyHtml: 'The controller never writes API tokens to status, Events, or request logs. Tunnel tokens and service-token secrets live only in Secrets.',
			},
		],
		more: { label: 'RBAC and API tokens', href: '/docs/operations/rbac-token/' },
	},

	tryIt: {
		heading: 'Try it: read the install before it runs.',
		ledeHtml:
			'<code>helm template</code> renders what the chart would install — no cluster, no Cloudflare credentials. Needs Helm 4.3 or a compatible Helm 3 client.',
		command: 'helm template flareway ./charts/flareway \\\n  --namespace flareway-system \\\n  --set gatewayClass.create=true',
		commandCaption: 'from a checkout of the repository',
		copy: 'Copy',
		copied: 'Copied',
		copyFailed: 'Select to copy',
		printsHeading: 'It prints',
		printsHtml: [
			'the controller Deployment',
			'RBAC',
			'Services',
			'NetworkPolicies',
			'<code>GatewayClass/flareway</code>, because <code>gatewayClass.create=true</code>',
			'its <code>GatewayClassConfig/default</code>',
		],
		notesHtml: [
			'Add <code>--include-crds</code> to also render the 22 Flareway CRDs the chart bundles.',
			'<code>gatewayClass.create</code> defaults to <code>false</code>, so an install cannot silently take ownership of an existing <code>GatewayClass</code>.',
		],
		primary: { label: 'Read the install guide', href: '/docs/operations/install/' },
		secondary: {
			label: 'Browse the sample manifests',
			href: 'https://github.com/isac322/flareway/tree/main/config/samples',
		},
	},

	star: {
		heading: 'About to write this operator yourself? Star it.',
		bodyHtml: 'Flareway is open source under Apache-2.0. Stars are how other platform engineers find it.',
		cta: 'Star on GitHub',
		ctaCount: '{count} stars',
		secondary: { label: 'Open an issue', href: 'https://github.com/isac322/flareway/issues' },
	},

	footer: {
		navLabel: 'Footer',
		tagline: 'Kubernetes Gateway API for Cloudflare Tunnel.',
		groups: [
			{
				heading: 'Operate',
				links: [
					{ label: 'Install', href: '/docs/operations/install/' },
					{ label: 'Upgrade', href: '/docs/operations/upgrade/' },
					{ label: 'RBAC and API tokens', href: '/docs/operations/rbac-token/' },
					{ label: 'Troubleshooting', href: '/docs/operations/troubleshooting/' },
				],
			},
			{
				heading: 'Reference',
				links: [
					{ label: 'API reference', href: '/docs/reference/api/' },
					{ label: 'kubectl explain guide', href: '/docs/reference/kubectl-explain/' },
					{ label: 'Architecture', href: '/docs/architecture/' },
					{ label: 'Gateway API conformance', href: '/docs/conformance/gateway-api-v1-6-2/' },
				],
			},
			{
				heading: 'Project',
				links: [
					{ label: 'GitHub', href: 'https://github.com/isac322/flareway' },
					{ label: 'Contributing', href: '/docs/project/contributing/' },
					{ label: 'Security policy', href: '/docs/project/security/' },
					{ label: 'License (Apache-2.0)', href: 'https://github.com/isac322/flareway/blob/main/LICENSE' },
				],
			},
		],
		top: 'Back to top',
	},
};
