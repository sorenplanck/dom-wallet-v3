# README Visual Identity Revision Report

**Owner:** Soren Planck <sorenplanck@tutamail.com>
**Result:** README_VISUAL_IDENTITY_COMPLETE

## Scope

This revision changes visual identity only. It updates the README badge colors and the standalone banner to follow the official DOM website's dark-bronze-paper visual language. README structure, technical content, project-status claims, implementation gates, security requirements, authorship rules, and links remain unchanged.

## Files changed

* `README.md`
* `assets/dom-wallet-v3-banner.svg`
* `reports/README_VISUAL_IDENTITY_REPORT.md`

## Palette mapping

| DOM token | Use in this revision |
|---|---|
| `#0a0807` black | Banner background and motif interior. |
| `#14100d` black-soft | Motif body. |
| `#2a2018` line | Fine ledger grid and boundary rules. |
| `#3d2f22` line-bright | Secondary ledger lines and circular structure. |
| `#b87333` bronze | Primary bronze accent and status badge. |
| `#d4914a` bronze-bright | Restrained rule and motif emphasis. |
| `#7a4a22` bronze-deep | Canonical-continuity paths and language badge. |
| `#8a6a3f` patina | Node accents and security-model badge. |
| `#e6ddd0` paper | Primary banner title. |
| `#b8aa97` paper-dim | Banner subtitle. |
| `#7d7060` fog | Technical labels and metadata. |

The previous navy, green, teal, cyan, and blue visual system was removed from the banner and badge colors.

## Typography hierarchy

The banner uses local fallback stacks only:

* Major title: `Cinzel, Georgia, Times New Roman, serif`.
* Technical labels: `IBM Plex Mono, SFMono-Regular, Consolas, Liberation Mono, monospace`.
* Supporting text: `Inter, Arial, Helvetica, sans-serif`.

No remote font, font import, image, script, event handler, external URL, remote stylesheet, or embedded JavaScript is present in the SVG.

## Banner geometry

The banner remains a standalone `1600 × 480` SVG with `viewBox="0 0 1600 480"`. It uses a near-black field, restrained bronze radial glow, fine ledger grid, horizontal boundary rules, and bounded geometric continuity lines. The title uses warm paper, the subtitle uses dim paper, and bronze-bright is reserved for small emphasis.

## Official symbol search

The DOM Protocol repository contains the raster DOM medallion at `wallet-desktop/ui/assets/dom-coin.png` and desktop icons derived from that asset. No clearly authoritative reusable vector symbol was found. The banner therefore retains an original temporary abstract motif based on circular monetary form, protected state, canonical continuity, and ledger geometry. It is not a new official protocol logo.

## Badge-color changes

The README retains the same four accurate badges and their labels. Only color values changed:

* Specification First Pass: `#b87333`.
* Rust: `#7a4a22`.
* DOM Wallet V3: `#3d2f22`.
* Specification Driven: `#8a6a3f`.

## Content-preservation confirmation

The README diff is limited to the four badge color tokens. The banner reference, README structure, substantive wording, technical content, status warnings, implementation gates, security requirements, authorship rules, and relative links are unchanged.

## Validation commands

```text
git status --porcelain --untracked-files=all
python3 -c 'import xml.etree.ElementTree as ET; ET.parse("assets/dom-wallet-v3-banner.svg")'
python3 -c 'from pathlib import Path; import re, sys; s = Path("assets/dom-wallet-v3-banner.svg").read_text(); bad = re.search(r"<(?:script|foreignObject|image)\\b|\\son[a-z]+\\s*=|javascript:|@import|<link\\b|font-face|url\\(\\s*(?:https?:|data:)", s, re.I); remote = re.search(r"https?://(?!www\\.w3\\.org/2000/svg)", s, re.I); sys.exit(bool(bad or remote))'
git diff --check
git diff -- README.md assets/dom-wallet-v3-banner.svg reports/README_VISUAL_IDENTITY_REPORT.md
```

Additional checks verify the authorized file set, absence of rejected color styling, absence of prohibited attribution, unchanged README technical content, and resolution of relative README links.

## Verdict

README_VISUAL_IDENTITY_COMPLETE
