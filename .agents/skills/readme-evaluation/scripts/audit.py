#!/usr/bin/env python3
"""Deterministic, offline, read-only audit helper for README review.

Observes a README source file and, optionally, renderer-produced GFM HTML of
the same source. Reports local link/anchor/image findings, descriptive
statistics, and explicit unknowns. It does not score quality, does not parse
full GFM semantics, never touches the network, and never executes commands
found in the document. All input is treated as untrusted data.

Usage:
    python3 audit.py README.md [--root DIR] [--html RENDERED.html]

Exit codes:
    0  audit completed (warnings/unknowns may be present in the report)
    1  deterministic failures found (broken local resources, escaping
       paths, malformed links, private/credential literals)
    2  input error (missing/unreadable README, invalid root, unreadable HTML)
"""

import argparse
import hashlib
import html.parser
import json
import os
import re
import sys
import urllib.parse

FENCE_RE = re.compile(r"^\s*(```|~~~)")
LINK_RE = re.compile(r"!?\[([^\]]*)\]\(([^)\s]+)(?:\s+[\"'(][^)]*)?\)")
REFDEF_RE = re.compile(r"^\s{0,3}\[([^\]]+)\]:\s*(\S+)")
REFUSE_RE = re.compile(r"!?\[([^\]]*)\]\[([^\]]*)\]")
AUTOLINK_RE = re.compile(r"<((?:https?|mailto):[^>\s]+)>")
INLINE_CODE_RE = re.compile(r"`[^`]*`")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
IMG_RE = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)")
EMPTY_LINK_RE = re.compile(
    r"!?\[([^\]]*)\]\(\s*#?\s*(?:\s+[\"'(][^)]*)?\)")
REVERSED_LINK_RE = re.compile(r"\(([^()\n]+)\)\[([^\]\n]+)\]")
SHORTCUT_REF_RE = re.compile(r"!?\[([^\]]+)\](?![\[(])")
# Public-repository hygiene literals. Loopback (127.0.0.0/8) and the
# RFC 5737 documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x)
# are intentionally not matched so intentional examples stay clean.
PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b")
CRED_RE = re.compile(r"\b(?:sk-|ghp_|gho_|token_)[A-Za-z0-9_-]{12,}")
BEARER_RE = re.compile(r"\bBearer\s+([A-Za-z0-9][A-Za-z0-9._~+/=-]{7,})")
SHELL_LANGS = {"sh", "bash", "shell", "console"}


def die(msg):
    print(json.dumps({"error": msg}), file=sys.stderr)
    sys.exit(2)


def github_slug(text):
    """Approximate GitHub's heading anchor slug (lowercase, spaces->hyphens,
    punctuation dropped). Used only as a fallback when no rendered HTML is
    available; duplicates get -1, -2 suffixes like GitHub."""
    text = re.sub(r"<[^>]+>", "", text)  # strip inline html tags
    text = re.sub(r"[`*_~\[\]]", "", text)
    slug = "".join(
        c if (c.isalnum() or c in " _-") else "" for c in text.lower()
    )
    return slug.replace(" ", "-")


def heading_anchors(texts):
    """Approximate GitHub anchor set from heading texts; duplicates get
    -1, -2 suffixes like GitHub."""
    anchors, seen = set(), {}
    for htext in texts:
        base = github_slug(htext)
        idx = seen.get(base, 0)
        seen[base] = idx + 1
        anchors.add(base if idx == 0 else f"{base}-{idx}")
    return anchors


def scan_source(text):
    """Split source into fenced-code vs prose lines; collect markdown links,
    images, headings, reference definitions, and fenced blocks. Not a GFM
    parser."""
    in_fence = False
    fence_marker = None
    cur_block = None
    prose_lines, code_lines = [], []
    headings = []  # (level, text, lineno)
    links = []  # dicts: kind, target, text, lineno
    malformed = []  # dicts: check, line, text, reason
    blocks = []  # dicts: lang, line, lines
    refdefs = {}  # label -> (target, lineno)
    ref_uses = []
    used_labels = set()

    for n, line in enumerate(text.splitlines(), 1):
        m = FENCE_RE.match(line)
        if m:
            marker = m.group(1)
            if not in_fence:
                in_fence, fence_marker = True, marker
                cur_block = {"lang": line[m.end():].strip().split()[0]
                             if line[m.end():].strip() else "",
                             "line": n, "lines": []}
            elif marker.startswith(fence_marker[0] * 3) or marker == fence_marker:
                in_fence, fence_marker = False, None
                if cur_block is not None:
                    blocks.append(cur_block)
                    cur_block = None
            code_lines.append(line)
            continue
        if in_fence:
            code_lines.append(line)
            if cur_block is not None:
                cur_block["lines"].append((n, line))
            continue
        prose_lines.append(line)

        hm = HEADING_RE.match(line)
        if hm:
            headings.append((len(hm.group(1)), hm.group(2), n))

        rd = REFDEF_RE.match(line)
        if rd:
            refdefs[rd.group(1).strip().lower()] = (rd.group(2), n)
            continue

        stripped = INLINE_CODE_RE.sub("", line)
        for am in AUTOLINK_RE.finditer(stripped):
            links.append({"kind": "autolink", "target": am.group(1),
                          "text": am.group(1), "line": n})
        for lm in LINK_RE.finditer(stripped):
            if lm.group(2) == "#":
                continue  # reported by EMPTY_LINK_RE below
            is_img = stripped[lm.start()] == "!"
            links.append({"kind": "image" if is_img else "link",
                          "target": lm.group(2), "text": lm.group(1),
                          "line": n})
        for em in EMPTY_LINK_RE.finditer(stripped):
            malformed.append({"check": "empty-link", "line": n,
                              "text": em.group(1),
                              "reason": "empty or placeholder link target; "
                                        "renders as an inert link"})
        for vm in REVERSED_LINK_RE.finditer(stripped):
            malformed.append({"check": "reversed-link", "line": n,
                              "text": vm.group(1),
                              "reason": "reversed link syntax (text)[url]; "
                                        "renders as literal text"})
        for rm in REFUSE_RE.finditer(stripped):
            ref_uses.append((rm.group(2) or rm.group(1), n,
                             stripped[rm.start()] == "!"))
        for sm in SHORTCUT_REF_RE.finditer(stripped):
            used_labels.add(sm.group(1).strip().lower())

    if cur_block is not None:
        blocks.append(cur_block)  # unclosed fence at EOF

    for label, n, is_img in ref_uses:
        used_labels.add(label.strip().lower())
        entry = refdefs.get(label.strip().lower())
        target = entry[0] if entry else f"[unresolved-ref:{label}]"
        links.append({"kind": "image" if is_img else "link",
                      "target": target, "text": label, "line": n})

    return {"prose_lines": prose_lines, "code_lines": code_lines,
            "headings": headings, "links": links, "malformed": malformed,
            "blocks": blocks, "refdefs": refdefs,
            "used_labels": used_labels}


class RenderedDoc(html.parser.HTMLParser):
    """Extract headings, ids, links, images, and prose/code text from
    renderer-produced GFM HTML. Renderer-generated heading anchor wrappers
    are skipped for prose statistics."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.headings = []  # (level, text)
        self.links = []  # (href, text)
        self.images = []  # (src, alt or None)
        self.prose_words = 0
        self.code_words = 0
        self.heading_words = 0
        self._stack = []
        self._heading_level = None
        self._heading_text = []
        self._link_href = None
        self._link_text = []
        self._skip_anchor = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self._stack.append(tag)
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "a" and a.get("name"):
            self.ids.add(a["name"])
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._heading_level = int(tag[1])
            self._heading_text = []
        if tag == "a":
            cls = a.get("class", "")
            if "anchor" in cls.split() and self._heading_level is not None:
                self._skip_anchor = True
                href = a.get("href", "")
                if href.startswith("#"):
                    self.ids.add(href[1:])
            elif a.get("href"):
                self._link_href = a["href"]
                self._link_text = []
        if tag == "img":
            self.images.append((a.get("src", ""), a.get("alt")))
        if tag == "source" and "srcset" in a:
            # <picture> candidates: take each candidate's URL, drop any
            # density/width descriptor. Alt lives on the sibling <img>.
            for candidate in a["srcset"].split(","):
                url = candidate.strip().split()[0] if candidate.strip() else ""
                if url:
                    self.images.append((url, ""))

    def handle_endtag(self, tag):
        if self._stack and self._stack[-1] == tag:
            self._stack.pop()
        elif tag in self._stack:
            while self._stack and self._stack.pop() != tag:
                pass
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6") and self._heading_level:
            self.headings.append(
                (self._heading_level, "".join(self._heading_text).strip()))
            self.heading_words += len("".join(self._heading_text).split())
            self._heading_level = None
        if tag == "a":
            if self._skip_anchor:
                self._skip_anchor = False
            elif self._link_href is not None:
                self.links.append(
                    (self._link_href, "".join(self._link_text).strip()))
                self._link_href = None

    def handle_data(self, data):
        if self._skip_anchor:
            return
        if self._heading_level is not None:
            self._heading_text.append(data)
        if self._link_href is not None:
            self._link_text.append(data)
        words = len(data.split())
        if not words:
            return
        if any(t in ("pre", "code", "script", "style") for t in self._stack):
            self.code_words += words
        elif self._heading_level is None:
            self.prose_words += words


def classify_target(target):
    """Return (category, decoded_path_or_None)."""
    if target.startswith("[unresolved-ref:"):
        return "unresolved-ref", None
    low = target.lower()
    if low.startswith(("http://", "https://", "mailto:", "ftp://", "tel:")):
        return "external", None
    if low.startswith(("javascript:", "data:", "vbscript:")):
        return "suspicious-scheme", None
    if target.startswith("#"):
        return "same-doc-anchor", urllib.parse.unquote(target[1:])
    if target.startswith("//"):
        return "external", None
    path, _, frag = target.partition("#")
    decoded = urllib.parse.unquote(path)
    if frag:
        return "cross-doc-anchor", decoded
    return "local-path", decoded


def resolve_local(root, readme_dir, decoded):
    """Resolve a decoded local path. Returns (abs_path, escaped)."""
    if decoded.startswith("/"):
        candidate = os.path.join(root, decoded.lstrip("/"))
    else:
        candidate = os.path.join(readme_dir, decoded)
    candidate = os.path.normpath(candidate)
    root_abs = os.path.normpath(os.path.abspath(root))
    cand_abs = os.path.normpath(os.path.abspath(candidate))
    escaped = not (cand_abs == root_abs or
                   cand_abs.startswith(root_abs + os.sep))
    return cand_abs, escaped


def main():
    ap = argparse.ArgumentParser(
        description="Offline read-only README audit helper (stdlib only).")
    ap.add_argument("readme", help="path to README markdown source")
    ap.add_argument("--root", default=".",
                    help="repository root for resolving root-leading paths")
    ap.add_argument("--html", default=None,
                    help="renderer-produced GFM HTML of the same source")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        die(f"root is not a directory: {args.root}")
    if not os.path.isfile(args.readme):
        die(f"README not found: {args.readme}")
    try:
        with open(args.readme, "rb") as f:
            raw = f.read()
    except OSError as e:
        die(f"README unreadable: {e}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        die(f"README is not valid UTF-8: {e}")

    readme_dir = os.path.dirname(os.path.abspath(args.readme))
    sha = hashlib.sha256(raw).hexdigest()

    rendered = None
    html_status = "omitted"
    if args.html:
        if not os.path.isfile(args.html):
            die(f"rendered HTML not found: {args.html}")
        try:
            with open(args.html, "r", encoding="utf-8") as f:
                html_text = f.read()
        except (OSError, UnicodeDecodeError) as e:
            die(f"rendered HTML unreadable: {e}")
        rendered = RenderedDoc()
        try:
            rendered.feed(html_text)
            rendered.close()
            html_status = "parsed"
            if not (rendered.ids or rendered.headings or
                    rendered.links or rendered.images):
                rendered = None
                html_status = ("no-markup: file contains no HTML elements; "
                               "not renderer output for this source")
        except Exception as e:  # malformed HTML -> unknown, not fake results
            rendered = None
            html_status = f"unparseable: {e}"

    src = scan_source(text)
    prose_lines, code_lines = src["prose_lines"], src["code_lines"]
    src_headings, src_links = src["headings"], src["links"]

    # Fallback anchor set from source headings when no rendered HTML.
    src_anchors = heading_anchors(h for _l, h, _n in src_headings)

    failures, warnings, unknowns = [], [], []
    local_checked = external = crossdoc = 0

    # Same-document anchors resolve against rendered ids when the renderer
    # emits them; otherwise approximate slugs from rendered headings, then
    # source headings. Approximate sets are recorded as unknown.
    if rendered is not None and rendered.ids:
        anchor_set = rendered.ids
    elif rendered is not None and rendered.headings:
        anchor_set = heading_anchors(h for _l, h in rendered.headings)
        unknowns.append({"check": "anchor-set",
                         "reason": "rendered HTML has no anchor ids; "
                                   "same-document anchors checked against "
                                   "approximate rendered-heading slugs"})
    else:
        anchor_set = src_anchors
        if rendered is not None:
            unknowns.append({"check": "anchor-set",
                             "reason": "rendered HTML has no anchor ids or "
                                       "headings; same-document anchors "
                                       "checked against approximate "
                                       "source-heading slugs"})

    def check_target(target, entry):
        nonlocal local_checked, external, crossdoc
        cat, decoded = classify_target(target)
        if cat == "external":
            external += 1
            return
        if cat == "suspicious-scheme":
            failures.append({**entry, "check": "scheme",
                             "reason": "non-web scheme in link target"})
            return
        if cat == "unresolved-ref":
            warnings.append({**entry, "check": "reference",
                             "reason": "reference-style link has no "
                                       "definition; renders as literal text "
                                       "— confirm the brackets are intended"})
            return
        if cat == "same-doc-anchor":
            ok = (decoded in anchor_set or
                  f"user-content-{decoded}" in anchor_set)
            if ok:
                local_checked += 1
            else:
                failures.append({**entry, "check": "anchor",
                                 "reason": "same-document anchor not found"})
            return
        # local-path or cross-doc-anchor
        if not decoded:
            return
        cand_abs, escaped = resolve_local(root, readme_dir, decoded)
        if escaped:
            failures.append({**entry, "check": "path-escape",
                             "reason": "local path escapes --root"})
            return
        if not os.path.exists(cand_abs):
            failures.append({**entry, "check": "local-exists",
                             "reason": "local target does not exist"})
            return
        local_checked += 1
        if cat == "cross-doc-anchor":
            crossdoc += 1
            unknowns.append({**entry, "check": "cross-doc-anchor",
                             "reason": "anchor inside another document is "
                                       "not verified (file exists)"})

    checked = set()
    for lk in src_links:
        dkey = "image" if lk["kind"] == "image" else "link"
        checked.add((dkey, lk["target"]))
        check_target(lk["target"],
                     {"line": lk["line"], "target": lk["target"],
                      "kind": lk["kind"], "origin": "source"})
    if rendered is not None:
        for href, _text in rendered.links:
            if not href or ("link", href) in checked:
                continue
            checked.add(("link", href))
            check_target(href, {"target": href, "kind": "link",
                                "origin": "rendered"})
        for img_src, _alt in rendered.images:
            if not img_src or ("image", img_src) in checked:
                continue
            checked.add(("image", img_src))
            check_target(img_src, {"target": img_src, "kind": "image",
                                   "origin": "rendered"})

    # Image alt review: presence is deterministic; quality is manual.
    for lk in src_links:
        if lk["kind"] != "image":
            continue
        if lk["text"].strip() == "":
            warnings.append({"line": lk["line"], "target": lk["target"],
                             "check": "image-alt",
                             "reason": "empty alt text; manual review needed "
                                       "to confirm image is decorative"})
    if rendered is not None:
        for img_src, alt in rendered.images:
            if alt is None:
                warnings.append({"target": img_src, "check": "image-alt",
                                 "reason": "rendered image has no alt "
                                           "attribute"})


    # Malformed link syntax found in source prose.
    for m in src["malformed"]:
        failures.append({"line": m["line"], "target": m["text"],
                         "check": m["check"], "reason": m["reason"]})

    # Heading structure: level skips and duplicate anchor slugs.
    prev_level = None
    slug_seen = {}
    for level, htext, lineno in src_headings:
        if prev_level is not None and level > prev_level + 1:
            warnings.append({"line": lineno, "check": "heading-skip",
                             "reason": f"heading jumps from h{prev_level} "
                                       f"to h{level}; skipped levels break "
                                       "the outline screen readers "
                                       "navigate"})
        prev_level = level
        base = github_slug(htext)
        if base in slug_seen:
            warnings.append({"line": lineno, "check": "duplicate-heading",
                             "reason": f"duplicate heading text; anchor "
                                       f"slug '{base}' collides with the "
                                       f"heading on line {slug_seen[base]}"})
        else:
            slug_seen[base] = lineno

    # Fenced code blocks: missing language and copyable shell prompts.
    for blk in src["blocks"]:
        if not blk["lang"]:
            warnings.append({"line": blk["line"], "check": "code-lang",
                             "reason": "fenced code block has no language "
                                       "info string; syntax highlighting "
                                       "and copy tooling degrade"})
        if blk["lang"].lower() in SHELL_LANGS:
            prompt_lines = [n for n, l in blk["lines"]
                            if l.startswith(("$ ", "# "))]
            if prompt_lines:
                warnings.append(
                    {"line": blk["line"], "check": "shell-prompt",
                     "reason": f"{blk['lang']} block contains "
                               f"prompt-prefixed lines "
                               f"{prompt_lines}; a reader copying them "
                               "gets a syntax error"})

    # Reference definitions never referenced.
    for label, (target, lineno) in src["refdefs"].items():
        if label not in src["used_labels"]:
            warnings.append({"line": lineno, "target": target,
                             "check": "unused-refdef",
                             "reason": f"reference definition [{label}] is "
                                       "never referenced"})

    # Public-repository hygiene: private network literals and
    # credential-looking strings anywhere in the source.
    for n, line in enumerate(text.splitlines(), 1):
        for ipm in PRIVATE_IP_RE.finditer(line):
            failures.append({"line": n, "target": ipm.group(0),
                             "check": "private-ip",
                             "reason": "private/internal address literal "
                                       "(RFC 1918 or Tailscale 100.64/10) "
                                       "in a public document"})
        for cm in CRED_RE.finditer(line):
            failures.append({"line": n, "target": cm.group(0)[:6] + "...",
                             "check": "credential-literal",
                             "reason": "credential-looking string "
                                       "(sk-/ghp_/gho_/token_ prefix); "
                                       "confirm it is a placeholder"})
        for bm in BEARER_RE.finditer(line):
            failures.append({"line": n, "target": "Bearer " +
                             bm.group(1)[:4] + "...",
                             "check": "credential-literal",
                             "reason": "'Bearer ' followed by a token "
                                       "literal; confirm it is a "
                                       "placeholder"})
    if rendered is None:
        unknowns.append({"check": "rendered",
                         "reason": "no --html given or HTML unparseable; "
                                   "rendered links/images/anchors unknown"})

    report = {
        "readme": os.path.abspath(args.readme),
        "root": root,
        "source_sha256": sha,
        "html": {"status": html_status,
                 "note": "HTML must be renderer-produced from this exact "
                         "source; a stale file makes rendered checks "
                         "unreliable. Compare source_sha256 with the "
                         "rendering input."},
        "stats": {
            "source_lines": len(text.splitlines()),
            "prose_lines": len(prose_lines),
            "code_lines": len(code_lines),
            "prose_words_source": len(
                " ".join(prose_lines).split()),
            "headings_source": len(src_headings),
            "links_total": len(src_links),
            "external_links_unchecked": external,
            "local_targets_checked": local_checked,
            "cross_doc_anchors_unknown": crossdoc,
        },
        "scope": {
            "checked": ["local file/dir existence inside root",
                        "same-document anchors",
                        "image alt presence",
                        "reversed and empty link syntax",
                        "heading level skips and duplicate heading slugs",
                        "fenced code language info strings",
                        "shell prompt prefixes in sh/bash/shell/console "
                        "blocks",
                        "unreferenced reference definitions",
                        "RFC 1918 / Tailscale 100.64/10 address literals",
                        "credential-looking literals (sk-, ghp_, gho_, "
                        "token_, 'Bearer <token>')"],
            "not_checked": ["external URLs (offline)",
                            "anchors inside other documents",
                            "alt text quality (manual)",
                            "whether flagged literals are live secrets "
                            "(manual)",
                            "loopback and RFC 5737 example addresses "
                            "(intentionally not flagged)",
                            "GFM semantics beyond link/heading extraction"],
        },
        "failures": failures,
        "warnings": warnings,
        "unknowns": unknowns,
    }
    if rendered is not None:
        report["rendered"] = {
            "headings": len(rendered.headings),
            "ids": len(rendered.ids),
            "links": len(rendered.links),
            "images": len(rendered.images),
            "prose_words": rendered.prose_words,
            "code_words": rendered.code_words,
            "heading_words": rendered.heading_words,
        }

    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
