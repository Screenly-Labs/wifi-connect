/**
 * Guardrails on the built portal.
 *
 * These assert properties of ui/dist that are invisible in review and
 * expensive in the field: they fail on the oldest phone someone uses to set
 * up a sign, where nobody can attach a debugger.
 */

import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const dist = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist')
const index = readFileSync(join(dist, 'index.html'), 'utf8')
const connecting = readFileSync(join(dist, 'connecting.html'), 'utf8')

/**
 * Strip HTML and CSS comments.
 *
 * These assertions are about what the browser *does*, and the prose in this
 * repo discusses the very things being forbidden — `user-scalable=no`,
 * `oklch`, CDN URLs. Matching raw source would fail on the documentation
 * that explains why the rule exists, which is the wrong incentive.
 */
function effective(html: string): string {
  return html.replace(/<!--[\s\S]*?-->/g, '').replace(/\/\*[\s\S]*?\*\//g, '')
}

const indexEff = effective(index)
const connectingEff = effective(connecting)

/** The content of a `<meta name="...">` tag, or '' if absent. */
function meta(html: string, name: string): string {
  const m = html.match(
    new RegExp(`<meta[^>]+name=["']${name}["'][^>]+content=["']([^"']*)["']`, 'i'),
  )
  return m?.[1] ?? ''
}

describe('single request', () => {
  test('nothing is loaded from outside the page', () => {
    // The portal has no internet access and mini-browsers are unreliable
    // about subresources, so every byte must already be in the document.
    for (const [name, html] of [
      ['index', indexEff],
      ['connecting', connectingEff],
    ] as const) {
      expect(html, `${name} links a stylesheet`).not.toMatch(/<link[^>]+rel=["']?stylesheet/i)
      expect(html, `${name} loads an external script`).not.toMatch(/<script[^>]+src=/i)
      expect(html, `${name} has an <img>`).not.toMatch(/<img[^>]+src=/i)
      // The checks that matter are resource *loads*, not any URL-shaped
      // string: Tailwind's preflight carries documentation links that the
      // browser never fetches.
      expect(html, `${name} @imports a remote stylesheet`).not.toMatch(/@import\s+["']?https?:/i)
      expect(html, `${name} url()s a remote asset`).not.toMatch(/url\(\s*["']?https?:/i)
    }
  })
})

describe('captive-portal browser compatibility', () => {
  test('no oklch() reaches the stylesheet', () => {
    // Tailwind v4's default palette is oklch, which needs Safari 15.4+.
    // tailwind.css clears that palette; this is the check that it worked.
    expect(indexEff).not.toMatch(/oklch\(/)
    expect(connectingEff).not.toMatch(/oklch\(/)
  })

  test('color-mix() only ever appears behind an @supports guard', () => {
    // We never write it ourselves (no `/opacity` modifiers, explicit alpha
    // tokens instead). Tailwind's preflight uses it for ::placeholder but
    // guards it, so an engine without color-mix just inherits currentColor.
    for (const html of [indexEff, connectingEff]) {
      const uses = (html.match(/color-mix\(/g) ?? []).length
      const guards = (html.match(/@supports\s*\(color:\s*color-mix\(/g) ?? []).length
      expect(uses).toBeLessThanOrEqual(guards * 2)
    }
  })

  test('the fallback comes first and nothing after it is wrapped in @layer', () => {
    // A browser that does not understand @layer DROPS it wholesale rather
    // than degrading, so a plain stylesheet has to come first and the
    // bundle after it must not be wrapped in one.
    const bodyRule = indexEff.indexOf('body{')
    const bodyRuleSpaced = indexEff.indexOf('body {')
    const firstBody = [bodyRule, bodyRuleSpaced].filter((i) => i >= 0).sort((a, b) => a - b)[0]

    expect(firstBody).toBeGreaterThan(-1)
    expect(firstBody, 'the fallback must come first').toBeLessThan(indexEff.indexOf('.wrap'))
    expect(indexEff, 'the bundle must be flattened out of @layer').not.toMatch(/@layer/)
    expect(connectingEff).not.toMatch(/@layer/)
  })

  test('the fallback is a floor, not a ceiling', () => {
    // Regression. skeleton.css is unlayered, and an unlayered normal
    // declaration beats a layered one at ANY specificity — so while the
    // bundle was wrapped in @layer, those forty lines were the last word on
    // the primary button, the fields and the network rows on EVERY
    // browser, not just the ancient ones they exist for.
    //
    // Nothing looked wrong, because the fallback's hardcoded #2563eb is
    // exactly what --color-accent resolves to in light mode. It showed up
    // only through --brand-css: an integrator could re-point every role
    // token and watch the Connect button stay blue.
    //
    // Both rules still ship. What this pins is their order, which is now
    // all that decides between them.
    const fallbackButton = indexEff.search(/\bbutton\s*\{[^}]*background:\s*#2563eb/)
    const themedButton = indexEff.search(/\.btn\s*\{[^}]*background:\s*var\(--color-accent\)/)
    expect(fallbackButton, 'the fallback button rule').toBeGreaterThan(-1)
    expect(themedButton, 'the themed button rule must come after it').toBeGreaterThan(
      fallbackButton,
    )

    // Same shape, and the one the screenshot gave away first: a stacked
    // row instead of name-and-signal on one line.
    const fallbackRow = indexEff.search(/\.net\s*\{[^}]*display:\s*block/)
    const themedRow = indexEff.search(/\.net\s*\{[^}]*display:\s*flex/)
    expect(fallbackRow).toBeGreaterThan(-1)
    expect(themedRow).toBeGreaterThan(fallbackRow)
  })

  test('layout uses flexbox, not grid or container queries', () => {
    expect(indexEff).not.toMatch(/@container/)
    expect(indexEff).not.toMatch(/display:\s*grid/)
  })
})

describe('theming', () => {
  test('dark mode has both a media arm and an attribute arm', () => {
    // The media arm carries no-JS and no-storage webviews; the attribute
    // arm lets the in-page toggle win. Either alone leaves a gap.
    expect(indexEff).toMatch(/prefers-color-scheme:\s*dark/)
    expect(indexEff).toMatch(/:root:where\(\[data-theme=["']?dark/)
  })

  test('the dark arms weigh no more than the roles they override', () => {
    // Tailwind emits the light roles into `:root, :host` (0,1,0) and both
    // dark arms follow it, so source order alone is enough for them to
    // win. Any extra weight is not just unnecessary, it is harmful:
    // `:root[data-theme="dark"]` is 0,2,0, which also puts the arm out of
    // reach of a --brand-css stylesheet's `:root` block — the documented
    // seam — and leaves an integrator branded in light and stock in dark.
    // :where() keeps the match and drops the weight.
    expect(indexEff, 'an arm heavier than :root').not.toMatch(/:root\[data-theme/)
    expect(indexEff, 'an arm heavier than :root').not.toMatch(/:root:not\(/)
    expect(indexEff).toMatch(/:root:where\(:not\(\[data-theme=["']?light/)
  })

  test('the media arm yields to an explicit light choice', () => {
    expect(indexEff).toMatch(/:root:where\(:not\(\[data-theme=["']?light/)
  })
})

describe('works without JavaScript', () => {
  test('the page is a real form that posts to /connect', () => {
    expect(index).toMatch(/<form[^>]+method=["']post["']/i)
    expect(index).toMatch(/action=["']\/connect["']/i)
    expect(index).toMatch(/<button[^>]+type=["']submit["']/i)
  })

  test('the password field carries native WPA validation', () => {
    // Catching a 7-character password here avoids a 30-second access-point
    // bounce that teaches the user nothing.
    expect(index).toMatch(/minlength=["']8["']/)
    expect(index).toMatch(/maxlength=["']63["']/)
  })

  test('the connecting page polls without JavaScript', () => {
    expect(connecting).toMatch(/http-equiv=["']refresh["']/i)
  })

  test('enhancement-only controls start hidden', () => {
    // Show/hide does nothing without JS, so it must not be visible to a
    // user who has none. The theme toggle is the same, but it is emitted
    // by the server now (only when the theme is not pinned), so its
    // `hidden` attribute is asserted in src/http/assets.rs instead.
    expect(index).toMatch(/id="pw-toggle"[^>]*hidden/)
    expect(index).toMatch(/\{\{THEME_TOGGLE\}\}/)
  })

  test('a pinned theme survives a stored preference', () => {
    // --default-theme renders data-theme on <html>. The boot script must
    // leave it alone: a phone that visited a differently-themed portal
    // earlier has a wc-theme in storage, and it does not get to overrule
    // the integrator.
    expect(index).toMatch(/\{\{THEME_ATTR\}\}/)
    expect(index).toMatch(/hasAttribute\(["']data-theme["']\)/)
    const guard = index.indexOf('hasAttribute')
    const read = index.indexOf('localStorage.getItem')
    expect(guard, 'the guard must come before the storage read').toBeLessThan(read)
  })
})

describe('mobile and accessibility', () => {
  test('zoom is not blocked on a password form', () => {
    // Assert on the viewport meta's own content: blocking pinch-zoom while
    // someone types a 63-character WPA passphrase is an accessibility
    // failure, and it is the one thing this tag can get wrong.
    const viewport = meta(index, 'viewport')
    expect(viewport).not.toContain('user-scalable=no')
    expect(viewport).not.toContain('maximum-scale')
  })

  test('the viewport covers the safe area', () => {
    expect(meta(index, 'viewport')).toContain('viewport-fit=cover')
    expect(indexEff).toMatch(/env\(safe-area-inset/)
  })

  test('inputs are at least 16px so iOS does not auto-zoom on focus', () => {
    expect(indexEff).toMatch(/font-size:\s*1rem/)
  })

  test('status regions are announced', () => {
    expect(connecting).toMatch(/aria-live=["']polite["']/)
    expect(index).toMatch(/<label[^>]+for=["']pw["']/)
  })

  test('reduced motion disables the spinner', () => {
    expect(connectingEff).toMatch(/prefers-reduced-motion/)
  })

  test('the document declares a language', () => {
    expect(index).toMatch(/<html[^>]+lang=["']en["']/)
  })
})

describe('captive-portal detection', () => {
  test('the page is never Apple’s success document', () => {
    // Apple's agent string-matches this exact body and would treat the
    // network as already open, so the sign-in sheet would never appear.
    expect(indexEff).not.toContain('<BODY>Success</BODY>')
    expect(indexEff).not.toContain('<TITLE>Success</TITLE>')
  })
})

describe('server-rendered placeholders', () => {
  test('the tokens the Rust side substitutes are present', () => {
    for (const token of ['{{BRAND_NAME}}', '{{NETWORKS}}', '{{BANNER}}']) {
      expect(index, `index.html lost ${token}`).toContain(token)
    }
    expect(connecting).toContain('{{SSID}}')
    expect(connecting).toContain('{{BRAND_NAME}}')
  })

  test('build-time tokens are fully substituted', () => {
    for (const html of [index, connecting]) {
      expect(html).not.toContain('{{STYLE}}')
      expect(html).not.toContain('{{SCRIPT}}')
    }
  })
})
