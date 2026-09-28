// Landing chart and interactions. Without this script the page still reads in
// full: sections, the diagram, the YAML, and every link are static HTML.
//
// The chart: the hero lockup sits on hachured land with an ink coastline; a
// wide orange channel leaves the lockup's opened door, doglegs at 18°,
// crosses the coast through a doorway, and runs down the left gutter as the
// page spine through a doorway notch in every section divider. It ends at the
// doorway above the star section. All geometry comes from the live layout and
// is rebuilt on resize and once fonts settle.

const NS = 'http://www.w3.org/2000/svg';
const T18 = Math.tan((18 * Math.PI) / 180);
/** Centre of the lockup's door notch at the cloud baseline, in lockup user units: MARK_TRANSFORM applied to (64, 113.5). */
const DOOR_FOOT = { x: 42 + 1.06 * 64, y: 42 + 1.06 * 113.5 };

type Point = [number, number];

function mk(tag: string, attrs: Record<string, string | number>, parent: Element): SVGElement {
	const el = document.createElementNS(NS, tag);
	for (const [name, value] of Object.entries(attrs)) el.setAttribute(name, String(value));
	parent.append(el);
	return el;
}

function bezier(a: Point, c1: Point, c2: Point, b: Point, t: number): Point {
	const m = 1 - t;
	return [
		m * m * m * a[0] + 3 * m * m * t * c1[0] + 3 * m * t * t * c2[0] + t * t * t * b[0],
		m * m * m * a[1] + 3 * m * m * t * c1[1] + 3 * m * t * t * c2[1] + t * t * t * b[1],
	];
}

function tangent(a: Point, c1: Point, c2: Point, b: Point, t: number): Point {
	const m = 1 - t;
	const d: Point = [
		3 * m * m * (c1[0] - a[0]) + 6 * m * t * (c2[0] - c1[0]) + 3 * t * t * (b[0] - c2[0]),
		3 * m * m * (c1[1] - a[1]) + 6 * m * t * (c2[1] - c1[1]) + 3 * t * t * (b[1] - c2[1]),
	];
	const length = Math.hypot(d[0], d[1]) || 1;
	return [d[0] / length, d[1] / length];
}

function startChart(reduced: boolean): void {
	const underlay = document.getElementById('underlay');
	const overlay = document.getElementById('overlay');
	const lockup = document.getElementById('hero-lockup') as SVGSVGElement | null;
	const hero = document.querySelector<HTMLElement>('.hero');
	const plate = document.querySelector<HTMLElement>('.plate');
	const heroWrap = document.querySelector<HTMLElement>('.hero .wrap');
	const endDivider = document.querySelector<HTMLElement>('.divider-end');
	const starMark = document.querySelector<SVGSVGElement>('.star-mark');
	if (!underlay || !overlay || !lockup || !hero || !plate || !heroWrap || !endDivider || !starMark) return;

	const notes = { opened: hero.dataset.noteOpened ?? '', noInbound: hero.dataset.noteNoInbound ?? '' };
	const text = (x: number, y: number, cls: string, value: string) => {
		mk('text', { x, y, class: cls }, underlay).append(value);
	};

	let signature = '';
	const started = performance.now();

	const layout = () => {
		const root = document.documentElement;
		const W = root.scrollWidth;
		const H = root.scrollHeight;
		const sx = window.scrollX;
		const sy = window.scrollY;
		const ctm = lockup.getScreenCTM();
		if (!ctm || !lockup.getBoundingClientRect().width) return;
		const foot = new DOMPoint(DOOR_FOOT.x, DOOR_FOOT.y).matrixTransform(ctm);
		const dcx = foot.x + sx;
		const dcy = foot.y + sy;
		const wrapRect = heroWrap.getBoundingClientRect();
		const contentLeft = wrapRect.left + sx + parseFloat(getComputedStyle(heroWrap).paddingLeft);
		const cw = parseFloat(getComputedStyle(root).getPropertyValue('--fw-landing-channel')) || 12;
		const gutX = Math.max(10, contentLeft - 30);
		const endY = endDivider.getBoundingClientRect().top + sy;
		const markRect = starMark.getBoundingClientRect();
		const endX = markRect.left + sx + markRect.width / 2;
		// The spine turns toward the star door inside the last section's bottom padding.
		const turnY = endY - 40;

		const key = [W, H, Math.round(dcx), Math.round(dcy), Math.round(gutX), Math.round(endY), Math.round(endX)].join('|');
		if (key === signature) return;
		// Rebuilds land in the final state instead of replaying the entrance, except
		// early rebuilds (fonts settling) that happen before anyone could see it.
		if (signature !== '' && performance.now() - started > 700) root.dataset.chartBuilt = '';
		signature = key;

		for (const svg of [underlay, overlay]) {
			svg.replaceChildren();
			svg.setAttribute('width', String(W));
			svg.setAttribute('height', String(H));
			svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
		}

		const defs = mk('defs', {}, underlay);
		const hach = mk(
			'pattern',
			{ id: 'chart-hach', class: 'l-hach', patternUnits: 'userSpaceOnUse', width: 7, height: 7, patternTransform: 'rotate(45)' },
			defs,
		);
		mk('line', { x1: 0, y1: 0, x2: 0, y2: 7 }, hach);

		const heroRect = hero.getBoundingClientRect();
		const hT = heroRect.top + sy;
		const hH = heroRect.height;
		const plateB = plate.getBoundingClientRect().bottom + sy;

		// Channel: door → straight down out of the plate's bottom frame → 18° dogleg
		// to the gutter below the plate → spine down the gutter → a run along the
		// last border to the star door, centred over the closing mark. The dogleg
		// stays below the plate so the channel never crosses the plate's text.
		// `dx` offsets a parallel line; on the run it offsets y the other way so
		// both fairway limits stay parallel through the turns.
		const stubY = Math.max(dcy + 16, plateB + 14);
		const bendY = stubY + Math.abs(dcx - gutX) * T18;
		const channel = (dx: number) =>
			`M ${dcx + dx} ${dcy} V ${stubY} L ${gutX + dx} ${bendY} V ${turnY - dx} H ${endX + dx} V ${endY - (dx === 0 ? cw / 2 : 0)}`;

		// Coastline: one curve crossing the channel through a doorway below the plate.
		// The wide coast needs the intro beside the plate; stacked layouts get the
		// compact coast that stays between the plate and the headline.
		const h1 = hero.querySelector<HTMLElement>('h1');
		const stacked = h1 !== null && h1.getBoundingClientRect().top + sy > plateB;
		const desk = !stacked;
		const px = gutX;
		const py = desk ? Math.max(bendY + 54, plateB + 84) : Math.max(bendY + 24, plateB + 30);
		const A: Point = [desk ? Math.max(0.46 * W, wrapRect.left + sx + 0.52 * wrapRect.width) : W + 6, desk ? hT - 6 : plateB - 18];
		const P: Point = [px, py];
		const B: Point = [-6, desk ? Math.max(hT + hH * 0.58, py + 0.12 * hH) : py + 12];
		const C1: Point = desk ? [A[0] - 0.06 * W, A[1] + 0.34 * hH] : [A[0] - 0.38 * W, A[1] + 28];
		const C2: Point = desk ? [px + 0.3 * W, py - 0.3 * hH] : [px + 0.56 * W, py - 56];
		const C3: Point = desk ? [px - 0.02 * W, py + 0.08 * hH] : [px - 20, py + 8];
		const C4: Point = desk ? [0.1 * W, Math.max(hT + 0.42 * hH, py + 0.04 * hH)] : [-60, B[1] - 4];
		const seg1 = `${A[0]} ${A[1]} C ${C1.join(' ')} ${C2.join(' ')} ${px} ${py}`;
		const seg2 = `C ${C3.join(' ')} ${C4.join(' ')} ${B[0]} ${B[1]}`;
		const landD = desk
			? `M -8 -8 L ${seg1} ${seg2} L -8 ${B[1]} Z`
			: `M -8 -8 L ${W + 8} -8 L ${seg1} ${seg2} L -8 ${B[1]} Z`;
		mk('path', { d: landD, class: 'l-land' }, underlay);
		mk('path', { d: landD, class: 'l-land-hach', fill: 'url(#chart-hach)' }, underlay);
		if (desk) mk('path', { d: `M ${seg1} ${seg2}`, class: 'l-contour', transform: 'translate(38 18)' }, underlay);
		mk('path', { d: `M ${seg1} ${seg2}`, class: 'l-coast' }, underlay);

		// Stacked layouts: keep the headline clear of the coast (24px plus the
		// stroke and sampling slack). Sample the curve over the h1's span and push
		// the intro block down through a custom property, then lay out again. The
		// compact coast depends only on the plate, so one extra pass settles it.
		if (h1 && stacked) {
			const r = h1.getBoundingClientRect();
			const shift = parseFloat(hero.style.getPropertyValue('--fw-landing-coast-clear')) || 0;
			const top = r.top + sy - shift;
			let coastY = -Infinity;
			for (let i = 0; i <= 100; i++) {
				for (const [x, y] of [bezier(A, C1, C2, P, i / 100), bezier(P, C3, C4, B, i / 100)]) {
					if (x >= r.left + sx && x <= r.right + sx) coastY = Math.max(coastY, y);
				}
			}
			const needed = Math.max(0, Math.ceil(coastY + 28 - top));
			if (Math.abs(needed - shift) > 1) {
				hero.style.setProperty('--fw-landing-coast-clear', `${needed}px`);
				signature = '';
				requestAnimationFrame(layout);
				return;
			}
		}

		// Blocked-inbound marks riding the coast, on the water side.
		const mark = (a: Point, c1: Point, c2: Point, b: Point, t: number, offset: number, label: boolean) => {
			const q = bezier(a, c1, c2, b, t);
			const u = tangent(a, c1, c2, b, t);
			const mx = q[0] + u[1] * offset;
			const my = q[1] - u[0] * offset;
			mk('path', { d: `M ${mx} ${my - 26} V ${my - 8}`, class: 'l-arr l-anim' }, underlay);
			mk('path', { d: `M ${mx - 5.5} ${my - 5.5} L ${mx + 5.5} ${my + 5.5} M ${mx + 5.5} ${my - 5.5} L ${mx - 5.5} ${my + 5.5}`, class: 'l-x l-anim' }, underlay);
			// On the compact coast the mark sits at the right edge, so its label reads
			// leftward; below 480px there is no room beside the plate, so it is omitted.
			if (label && desk) text(mx + 10, my - 10, 'l-note l-anim', notes.noInbound);
			else if (label && W >= 480) mk('text', { x: mx - 12, y: my - 10, class: 'l-note l-anim', 'text-anchor': 'end' }, underlay).append(notes.noInbound);
		};
		if (desk) {
			mark(A, C1, C2, P, 0.08, 26, false);
			mark(P, C3, C4, B, 0.3, 30, true);
		} else {
			mark(A, C1, C2, P, 0.14, 30, true);
		}
		text(dcx + cw / 2 + (desk ? 20 : 14), plateB + (desk ? 34 : 26), 'l-note-ink l-anim', notes.opened);

		// A doorway notch: the border opens across the channel, framed by two ink jambs.
		const doorway = (x: number, y: number, parent: Element) => {
			mk('rect', { x: x - cw / 2 - 8, y: y - 3, width: cw + 16, height: 7, class: 'gap' }, parent);
			for (const side of [1, -1]) {
				const bx = x + side * (cw / 2 + 8);
				mk('path', { d: `M ${bx} ${y - 6} L ${bx} ${y + 6}`, class: 'l-tick' }, parent);
			}
		};
		doorway(px, py, underlay);

		// The plate's bottom edge opens where the channel leaves it.
		mk('rect', { x: dcx - cw / 2 - 6, y: plateB - 2, width: cw + 12, height: 4, class: 'gap' }, overlay);

		// Channel and its dashed fairway limits.
		const limit = cw / 2 + 4.5;
		mk('path', { d: channel(-limit), class: 'lim' }, overlay);
		mk('path', { d: channel(limit), class: 'lim' }, overlay);
		mk('path', { d: channel(0), class: 'chan', 'stroke-width': cw, pathLength: 1 }, overlay);

		// A doorway notch in every divider: on the spine above the star door, and on
		// the star room's axis below it (the footer border).
		for (const divider of document.querySelectorAll<HTMLElement>('.divider')) {
			if (divider === endDivider) continue;
			const dy = divider.getBoundingClientRect().top + sy;
			doorway(dy > endY ? endX : gutX, dy, overlay);
		}

		// The star door, where the channel ends: a wide opening in the last border,
		// centred over the closing mark, its leaf swung into the room (plan symbol,
		// as in the diagram).
		const doorW = cw + 48;
		const hingeX = endX + doorW / 2;
		const leafEnd: Point = [hingeX - doorW * Math.sin((18 * Math.PI) / 180), endY + doorW * Math.cos((18 * Math.PI) / 180)];
		mk('rect', { x: endX - doorW / 2 - 2, y: endY - 3, width: doorW + 4, height: 7, class: 'gap' }, overlay);
		for (const side of [1, -1]) {
			const bx = endX + side * (doorW / 2);
			mk('path', { d: `M ${bx} ${endY - 10} L ${bx} ${endY + 10}`, class: 'l-tick l-tick-end' }, overlay);
		}
		mk('path', { d: `M ${endX - doorW / 2} ${endY} A ${doorW} ${doorW} 0 0 0 ${leafEnd[0]} ${leafEnd[1]}`, class: 'l-swing' }, overlay);
		mk('path', { d: `M ${hingeX} ${endY} L ${leafEnd[0]} ${leafEnd[1]}`, class: 'l-leaf l-leaf-end' }, overlay);

		// A request rides the channel inbound once, from the star door up to the hero door, and parks there.
		if (!reduced) {
			const dot = mk('circle', { r: 4.5, class: 'd-dot', opacity: 0 }, overlay);
			mk('set', { attributeName: 'opacity', to: 1, begin: '2.5s', fill: 'freeze' }, dot);
			mk('animateMotion', { dur: '5.5s', begin: '2.5s', fill: 'freeze', calcMode: 'paced', path: `M ${endX} ${endY} V ${turnY} H ${gutX} V ${bendY} L ${dcx} ${stubY} V ${dcy}` }, dot);
		}
	};

	requestAnimationFrame(layout);
	window.addEventListener('resize', layout);
	window.addEventListener('load', layout);
	document.fonts?.ready.then(layout);
}

function startCopyButtons(): void {
	for (const button of document.querySelectorAll<HTMLButtonElement>('button.copy[data-copy]')) {
		const label = button.textContent ?? '';
		button.addEventListener('click', async () => {
			try {
				await navigator.clipboard.writeText(button.dataset.copy ?? '');
				button.textContent = button.dataset.copied ?? label;
				button.dataset.done = '';
			} catch {
				button.textContent = button.dataset.copyFailed ?? label;
			}
			setTimeout(() => {
				button.textContent = label;
				delete button.dataset.done;
			}, 1600);
		});
	}
}

/** Demo: an output highlights the YAML lines behind it (`g:2,7-12;r:10-11`). */
function startLineHighlights(): void {
	const outputs = [...document.querySelectorAll<HTMLButtonElement>('button.out[data-lines]')];
	if (outputs.length === 0) return;
	const files = new Map([...document.querySelectorAll<HTMLElement>('pre[data-file]')].map((pre) => [pre.dataset.file, pre]));
	const linesFor = (spec: string) =>
		spec.split(';').flatMap((part) => {
			const [file, ranges = ''] = part.split(':');
			const pre = files.get(file);
			if (!pre) return [];
			return ranges.split(',').flatMap((range) => {
				const [from, to = from] = range.split('-').map(Number);
				return Array.from({ length: to - from + 1 }, (_, i) => pre.children[from - 1 + i]).filter(Boolean);
			});
		});
	const clear = () => {
		for (const el of document.querySelectorAll('.l.hl')) el.classList.remove('hl');
		for (const out of outputs) {
			out.classList.remove('on');
			out.setAttribute('aria-pressed', 'false');
		}
	};
	const show = (out: HTMLButtonElement) => {
		clear();
		out.classList.add('on');
		for (const line of linesFor(out.dataset.lines ?? '')) line.classList.add('hl');
	};
	for (const out of outputs) {
		out.addEventListener('mouseenter', () => show(out));
		out.addEventListener('focus', () => show(out));
		out.addEventListener('click', () => {
			show(out);
			out.setAttribute('aria-pressed', 'true');
		});
	}
	outputs[0].closest('ol')?.addEventListener('mouseleave', clear);
	outputs[0].closest('ol')?.addEventListener('focusout', (event) => {
		if (!(event.currentTarget as Element).contains(event.relatedTarget as Node | null)) clear();
	});
}

export function startLanding(): void {
	const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
	// Reduced motion: SMIL pulses in the diagram are removed; CSS shows every
	// chart element in its final state.
	if (reduced) for (const motion of document.querySelectorAll('animateMotion')) motion.remove();
	startChart(reduced);
	startCopyButtons();
	startLineHighlights();
}
