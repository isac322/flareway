// @ts-check
import starlight from '@astrojs/starlight';
import { ExpressiveCodeTheme } from '@astrojs/starlight/expressive-code';
import { defineConfig } from 'astro/config';
import { BRAND_ORANGE } from './src/components/brand/paths.ts';
import { starlightSidebar } from './src/data/nav.ts';

const siteUrl = 'https://flareway.bhyoo.com';

/** Resolve a `--fw-code-*` token from src/styles/tokens.css. */
const code = (/** @type {string} */ name) => `var(--fw-code-${name})`;
const codeHairline = (/** @type {number} */ percent) =>
	`color-mix(in srgb, ${code('ink')} ${percent}%, transparent)`;

/**
 * Code blocks match the landing's code panels: a navy panel in both site
 * themes, drawn with the `--fw-code-*` tokens so colors stay in tokens.css.
 * Expressive Code needs one theme per site theme to scope its styles to
 * `[data-theme='dark'|'light']`; both carry the same token colors. The
 * constructor only accepts hex workbench colors, so the placeholders below are
 * immediately replaced by token references and never reach the page.
 */
function flarewayCodeTheme(/** @type {'dark' | 'light'} */ type) {
	const theme = new ExpressiveCodeTheme({
		name: `flareway-${type}`,
		type,
		colors: { 'editor.background': '#000000', 'editor.foreground': '#ffffff' },
		tokenColors: [
			{ scope: ['comment', 'punctuation.definition.comment'], settings: { foreground: code('dim'), fontStyle: 'italic' } },
			{
				scope: [
					'entity.name.tag',
					'support.type.property-name',
					'meta.object-literal.key',
					'keyword',
					'storage',
					'entity.name.function',
					'support.function',
					'entity.name.type',
					'constant.numeric',
					'constant.language',
				],
				settings: { foreground: code('key') },
			},
			{ scope: ['punctuation', 'meta.brace', 'keyword.operator'], settings: { foreground: code('dim') } },
			{ scope: ['string', 'variable', 'constant.other', 'entity.other'], settings: { foreground: code('ink') } },
		],
	});
	theme.bg = code('bg');
	theme.fg = code('ink');
	Object.assign(theme.colors, {
		'editor.background': code('bg'),
		'editor.foreground': code('ink'),
		'editorGroupHeader.tabsBackground': code('bg'),
		'editorGroupHeader.tabsBorder': codeHairline(10),
		'tab.activeBackground': code('bg'),
		'tab.activeForeground': code('ink'),
		'tab.activeBorderTop': 'transparent',
		'tab.activeBorder': 'transparent',
		'titleBar.activeBackground': code('bg'),
		'titleBar.activeForeground': code('dim'),
		'titleBar.border': codeHairline(10),
		'terminal.background': code('bg'),
		'widget.shadow': 'transparent',
	});
	return theme;
}

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
			// tokens.css first: docs.css maps Starlight's variables onto its --fw-* tokens.
			customCss: ['./src/styles/tokens.css', './src/styles/docs.css'],
			expressiveCode: {
				themes: [flarewayCodeTheme('dark'), flarewayCodeTheme('light')],
				// Token colors are CSS variables; contrast is guaranteed by the token palette.
				minSyntaxHighlightingColorContrast: 0,
				styleOverrides: {
					borderRadius: '10px',
					borderColor: 'var(--fw-line)',
					codeBackground: code('bg'),
					codeForeground: code('ink'),
					codeSelectionBackground: code('hl'),
					codeFontSize: '0.875rem',
					codeLineHeight: '1.65',
					uiSelectionBackground: code('hl'),
					uiSelectionForeground: code('ink'),
					gutterForeground: code('gutter'),
					gutterHighlightForeground: code('ink'),
					gutterBorderColor: codeHairline(12),
					scrollbarThumbColor: codeHairline(20),
					scrollbarThumbHoverColor: codeHairline(35),
					focusBorder: 'var(--fw-accent)',
					uiFontSize: '0.8125rem',
					frames: {
						frameBoxShadowCssValue: 'var(--fw-shadow)',
						editorActiveTabIndicatorHeight: '0px',
						editorTabBarBorderBottomColor: codeHairline(10),
						terminalTitlebarDotsForeground: code('dim'),
						terminalTitlebarDotsOpacity: '0.5',
						inlineButtonForeground: code('dim'),
						inlineButtonBorder: code('ink'),
						inlineButtonBorderOpacity: '0.18',
						inlineButtonBackgroundHoverOrFocusOpacity: '0.12',
						inlineButtonBackgroundActiveOpacity: '0.2',
						tooltipSuccessBackground: code('key'),
						tooltipSuccessForeground: code('bg'),
					},
					textMarkers: {
						markBackground: code('hl'),
						markBorderColor: 'var(--fw-accent)',
					},
				},
			},
			components: {
				Header: './src/components/starlight/Header.astro',
				SiteTitle: './src/components/starlight/SiteTitle.astro',
				Sidebar: './src/components/starlight/Sidebar.astro',
				Pagination: './src/components/starlight/Pagination.astro',
				Footer: './src/components/starlight/Footer.astro',
			},
			head: [
				{ tag: 'link', attrs: { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' } },
				{ tag: 'meta', attrs: { property: 'og:image', content: `${siteUrl}/og.png` } },
				{ tag: 'meta', attrs: { property: 'og:image:width', content: '1280' } },
				{ tag: 'meta', attrs: { property: 'og:image:height', content: '640' } },
				{ tag: 'meta', attrs: { property: 'og:site_name', content: 'Flareway' } },
				{ tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
				{ tag: 'meta', attrs: { name: 'twitter:image', content: `${siteUrl}/og.png` } },
				{ tag: 'meta', attrs: { name: 'theme-color', content: BRAND_ORANGE } },
			],
		}),
	],
});
