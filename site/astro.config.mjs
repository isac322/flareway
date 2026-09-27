// @ts-check
import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';
import { starlightSidebar } from './src/data/nav.ts';

const siteUrl = 'https://flareway.bhyoo.com';

export default defineConfig({
	site: siteUrl,
	integrations: [
		starlight({
			title: 'Flareway',
			description:
				'Kubernetes Gateway API on Cloudflare Tunnel with an in-pod Envoy data plane, plus Cloudflare Access and WARP as CRDs.',
			favicon: '/favicon.svg',
			// src/pages/404.astro renders the not-found page through StarlightPage.
			disable404Route: true,
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/isac322/flareway' }],
			// Edit links point at the original repository file: the sync script
			// writes each page's `editUrl` frontmatter from its source path.
			sidebar: [...starlightSidebar],
			customCss: ['./src/styles/docs.css'],
			components: {
				Header: './src/components/starlight/Header.astro',
				SiteTitle: './src/components/starlight/SiteTitle.astro',
				Sidebar: './src/components/starlight/Sidebar.astro',
				Pagination: './src/components/starlight/Pagination.astro',
			},
			head: [
				{ tag: 'link', attrs: { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' } },
				{ tag: 'meta', attrs: { property: 'og:image', content: `${siteUrl}/og.png` } },
				{ tag: 'meta', attrs: { property: 'og:image:width', content: '1280' } },
				{ tag: 'meta', attrs: { property: 'og:image:height', content: '640' } },
				{ tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
				{ tag: 'meta', attrs: { name: 'twitter:image', content: `${siteUrl}/og.png` } },
				{ tag: 'meta', attrs: { name: 'theme-color', content: '#E77B35' } },
			],
		}),
	],
});
