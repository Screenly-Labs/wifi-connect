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
  return [
    '@media (prefers-color-scheme: dark) {',
    '  :root:not([data-theme="light"]) {',
    roles,
    '  }',
    '}',
    ':root[data-theme="dark"] {',
    roles,
    '}',
  ].join('\n')
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

  // Order matters: the unlayered skeleton comes FIRST so that a browser
  // which understands @layer lets the Tailwind layer override it, while one
  // that does not — and therefore drops the Tailwind block wholesale —
  // still has a plain, usable stylesheet.
  //
  // The skeleton and the generated dark block are hand-written and so still
  // carry their comments; Tailwind's output is already minified. Strip them
  // on the way out: the page ships to a device over a setup hotspot, and
  // the rationale belongs in the source, not in every byte served.
  const style = [stripCssComments(skeleton), tailwind, stripCssComments(dark)].join('\n')

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
  }

  // A worked example for integrators: override roles, never primitives.
  await writeFile(
    join(dist, 'brand.example.css'),
    `/* Served at /brand.css when --brand-css points here.
 *
 * Loaded last, so it overrides the role tokens. Override ROLES only --
 * never the --c-* primitives and never the markup -- and a rebrand cannot
 * come adrift when the portal's layout changes.
 */
:root {
  --color-accent: #ea4aaa;
  --color-accent-hover: #d43d98;
  --color-on-accent: #ffffff;
  --color-focus-ring: rgb(234 74 170 / 0.45);
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
