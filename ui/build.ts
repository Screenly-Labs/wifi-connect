/**
 * Portal build.
 *
 * Produces ui/dist/{index,connecting}.html, each a SINGLE self-contained
 * request: CSS and JS are inlined rather than linked.
 *
 * That is not an optimisation. Captive-portal mini-browsers are unreliable
 * about fetching subresources, and a portal whose stylesheet or script
 * silently fails to load is a portal that looks broken on exactly the
 * devices least able to recover from it. One request, one outcome.
 *
 * The output is COMMITTED to the repository, so `cargo build` never needs
 * bun. CI re-runs this and fails if the committed output has drifted.
 */

import { $ } from 'bun'
import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const src = join(here, 'src')
const tmp = join(here, '.tmp')
const dist = join(here, 'dist')

/**
 * Emit the dark-theme role block under both selectors it needs.
 *
 * The roles are authored once in css/theme-dark.css between the
 * `@dark-roles` markers. They have to appear twice in the output:
 *
 *   - under @media (prefers-color-scheme: dark), which is what carries the
 *     no-JavaScript case and the webviews with no storage to read a
 *     preference from;
 *   - under :root[data-theme="dark"], so the in-page toggle wins in both
 *     directions.
 *
 * Maintaining two copies by hand is how they drift, so they are generated.
 * The `:not([data-theme="light"])` guard stops the media arm overriding an
 * explicit light choice.
 */
async function darkThemeCss(): Promise<string> {
  const source = await readFile(join(src, 'css/theme-dark.css'), 'utf8')
  const match = source.match(/@dark-roles:start\s*\*\/([\s\S]*?)\/\*\s*@dark-roles:end/)
  if (!match) throw new Error('theme-dark.css is missing its @dark-roles markers')

  const roles = match[1].trim()
  // :where() around the qualifying part, so each arm weighs exactly as much
  // as the `:root` that sets the light defaults and wins on order alone.
  //
  // Written the obvious way — `:root:not([data-theme="light"])` — an arm
  // weighs 0,2,0 and beats a brand stylesheet's `:root` block no matter
  // what order they load in, so an integrator who sets --color-accent gets
  // their colour in light mode and ours in dark. The seam has to hold in
  // both, and an integrator cannot be asked to restate our internal
  // selectors to get there.
  return [
    '@media (prefers-color-scheme: dark) {',
    '  :root:where(:not([data-theme="light"])) {',
    roles,
    '  }',
    '}',
    ':root:where([data-theme="dark"]) {',
    roles,
    '}',
  ].join('\n')
}

/**
 * Unwrap every `@layer` block, keeping the rules and their order.
 *
 * Cascade layers do NOT lose to document order — a normal declaration
 * outside a layer beats one inside, at any specificity. So the unlayered
 * skeleton below was overriding the design system on every browser, not
 * just the ancient ones it exists for: `button{background:#2563eb}` beat
 * `@layer components{.btn{background:var(--color-accent)}}`, which is why
 * the default palette (--c-accent-600 is that same blue) hid it, and why
 * a --brand-css that re-pointed --color-accent changed nothing on the one
 * control that matters.
 *
 * Flattening puts the whole bundle on the same footing as the skeleton,
 * where specificity and order decide: `.btn` beats `button`, the Tailwind
 * reset follows the skeleton rather than yielding to it, and brand.css —
 * last in the document — wins. The layers earn nothing here anyway; this
 * portal has no utility/component conflicts to arbitrate, and the emitted
 * order already matches the layer order.
 *
 * The scan is quote-aware because a declaration may legitimately carry a
 * brace inside a string.
 */
function flattenCssLayers(css: string): string {
  let out = ''
  let i = 0

  while (i < css.length) {
    const at = css.indexOf('@layer', i)
    if (at === -1) {
      out += css.slice(i)
      break
    }
    out += css.slice(i, at)

    // The name list runs to either `;` (an ordering statement, which has
    // no rules to keep) or `{` (a block to unwrap).
    let head = at + '@layer'.length
    while (head < css.length && css[head] !== '{' && css[head] !== ';') head += 1
    if (css[head] === ';') {
      i = head + 1
      continue
    }

    let depth = 1
    let end = head + 1
    let quote = ''
    while (end < css.length && depth > 0) {
      const ch = css[end]
      if (quote) {
        if (ch === '\\') end += 1
        else if (ch === quote) quote = ''
      } else if (ch === '"' || ch === "'") {
        quote = ch
      } else if (ch === '{') {
        depth += 1
      } else if (ch === '}') {
        depth -= 1
      }
      end += 1
    }
    if (depth !== 0) throw new Error('unbalanced @layer block in the Tailwind output')

    out += flattenCssLayers(css.slice(head + 1, end - 1))
    i = end
  }

  return out
}

/**
 * Drop `/* ... *\/` blocks and collapse the whitespace they leave behind.
 *
 * CSS has no nested comments, so a non-greedy scan is exact here. Strings
 * containing the sequence would be a hazard in general, but these two
 * stylesheets are hand-written and contain none.
 */
function stripCssComments(css: string): string {
  return css
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\n{2,}/g, '\n')
    .trim()
}

/**
 * The CSP source expression for every inline `<tag>` block in `html`.
 *
 * The server sends a Content-Security-Policy that allows inline script and
 * style ONLY by hash, so the hashes have to be of the exact bytes the
 * browser sees between the tags. They are taken from the finished page
 * rather than from the inputs to it, which is the only way to be sure the
 * newline and indentation around each block are counted the way the
 * browser counts them.
 *
 * The Rust side substitutes its tokens into the page after this, but only
 * into markup and text, never into these bodies, and a test there
 * recomputes every hash from the rendered page to keep it that way.
 */
function inlineHashes(html: string, tag: 'script' | 'style'): string[] {
  const block = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, 'g')
  return [...html.matchAll(block)].map(
    (m) => `'sha256-${createHash('sha256').update(m[1], 'utf8').digest('base64')}'`,
  )
}

async function build(): Promise<void> {
  await mkdir(tmp, { recursive: true })
  await mkdir(dist, { recursive: true })

  await $`bun x @tailwindcss/cli -i ${join(src, 'tailwind.css')} -o ${join(tmp, 'portal.css')} --minify`.quiet()

  const built = await Bun.build({
    entrypoints: [join(src, 'portal.ts')],
    target: 'browser',
    // Whitespace and syntax only. --minify-identifiers is avoided for the
    // same reason Anthias avoids it: renaming identifiers can break
    // runtime-evaluated expression lookups, and the saving is not worth a
    // silent failure on a page nobody can debug remotely.
    minify: { whitespace: true, syntax: true, identifiers: false },
  })
  if (!built.success) {
    throw new AggregateError(built.logs, 'portal.ts failed to build')
  }

  const [skeleton, tailwind, dark, script] = await Promise.all([
    readFile(join(src, 'css/skeleton.css'), 'utf8'),
    readFile(join(tmp, 'portal.css'), 'utf8'),
    darkThemeCss(),
    built.outputs[0].text(),
  ])

  // Order matters: the skeleton comes FIRST so that a browser which drops
  // what it cannot parse still has a plain, usable stylesheet, and every
  // rule after it overrides it on a browser that can.
  //
  // That second half only holds because the Tailwind bundle is flattened
  // out of its @layer blocks on the way in — unlayered beats layered
  // whatever the order, so while the layers were intact the forty-line
  // fallback was quietly the last word on buttons, fields and rows. See
  // flattenCssLayers.
  //
  // The skeleton and the generated dark block are hand-written and so still
  // carry their comments; Tailwind's output is already minified. Strip them
  // on the way out: the page ships to a device over a setup hotspot, and
  // the rationale belongs in the source, not in every byte served.
  const style = [
    stripCssComments(skeleton),
    flattenCssLayers(tailwind),
    stripCssComments(dark),
  ].join('\n')

  const scriptHashes = new Set<string>()
  const styleHashes = new Set<string>()

  for (const page of ['index', 'connecting']) {
    const html = await readFile(join(src, `${page}.html`), 'utf8')
    // The markers are HTML comments, not {{tokens}} inside <style>/<script>
    // elements: prettier parses those element bodies as CSS and JS and
    // would rewrite a bare token into something that no longer matches.
    const out = html
      .replace('<!--STYLE-->', () => `<style>\n${style}\n</style>`)
      .replace('<!--SCRIPT-->', () => `<script>\n${script}\n</script>`)
      // Substituted at render time, not here: the link must appear ONLY
      // when --brand-css is set, so an unbranded portal keeps the
      // single-request property this file's test asserts.
      .replace('<!--BRAND-->', () => '{{BRAND_CSS}}')
    await writeFile(join(dist, `${page}.html`), out, 'utf8')

    for (const h of inlineHashes(out, 'script')) scriptHashes.add(h)
    for (const h of inlineHashes(out, 'style')) styleHashes.add(h)
  }

  // Read by src/http/assets.rs to build the Content-Security-Policy. Only
  // the hashes live here; the policy itself is written in Rust, next to
  // the routes it has to agree with. Sorted so an unchanged UI rebuilds to
  // an unchanged file.
  await writeFile(
    join(dist, 'csp.json'),
    `${JSON.stringify({ script: [...scriptHashes].sort(), style: [...styleHashes].sort() }, null, 2)}\n`,
    'utf8',
  )

  // A worked example for integrators: override roles, never primitives.
  await writeFile(
    join(dist, 'brand.example.css'),
    `/* Served at /brand.css when --brand-css points here.
 *
 * Loaded last, so it overrides the role tokens. Override ROLES only --
 * never the --c-* primitives and never the markup -- and a rebrand cannot
 * come adrift when the portal's layout changes.
 *
 * The block below is the whole job: the portal's own dark arms carry no
 * more weight than the light defaults, so one :root block brands BOTH
 * schemes.
 */
:root {
  --color-accent: #ea4aaa;
  --color-accent-hover: #d43d98;
  --color-on-accent: #ffffff;
  --color-focus-ring: rgb(234 74 170 / 0.45);
}

/* Only needed to use a DIFFERENT value in dark rather than the same one in
 * both. It takes two arms for the same reason the portal has two: the media
 * query carries a webview with no JS or no storage, and the attribute
 * carries the in-page theme toggle. Either alone leaves a gap.
 */
@media (prefers-color-scheme: dark) {
  :root:not([data-theme='light']) {
    --color-accent: #f472b6;
    --color-on-accent: #2a0a1c;
  }
}

:root[data-theme='dark'] {
  --color-accent: #f472b6;
  --color-on-accent: #2a0a1c;
}
`,
    'utf8',
  )

  const bytes = (await readFile(join(dist, 'index.html'))).byteLength
  console.log(`built ui/dist/index.html (${(bytes / 1024).toFixed(1)} kB, single request)`)
}

await build()
