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
  const m = html.match(new RegExp(`<meta[^>]+name=["']${name}["'][^>]+content=["']([^"']*)["']`, 'i'))
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

  test('an unlayered fallback precedes the @layer block', () => {
    // A browser that does not understand @layer DROPS it wholesale rather
    // than degrading, so a plain stylesheet has to come first.
    const firstLayer = indexEff.indexOf('@layer')
    const bodyRule = indexEff.indexOf('body{')
    const bodyRuleSpaced = indexEff.indexOf('body {')
    const firstBody = [bodyRule, bodyRuleSpaced].filter((i) => i >= 0).sort((a, b) => a - b)[0]

    expect(firstBody).toBeGreaterThan(-1)
    expect(firstBody, 'the unlayered skeleton must precede @layer').toBeLessThan(firstLayer)
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
    expect(indexEff).toMatch(/:root\[data-theme=["']?dark/)
  })

  test('the attribute arm outranks Tailwind’s :root', () => {
    // Tailwind emits into `:root, :host` (0,1,0). A bare attribute
    // selector would only tie and lose on source order.
    expect(indexEff).toMatch(/:root\[data-theme=["']?dark["']?\]/)
  })

  test('the media arm yields to an explicit light choice', () => {
    expect(indexEff).toMatch(/:root:not\(\[data-theme=["']?light/)
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
    // Show/hide and the theme toggle do nothing without JS, so they must
    // not be visible to a user who has none.
    expect(index).toMatch(/id="pw-toggle"[^>]*hidden/)
    expect(index).toMatch(/id="theme-toggle"[^>]*hidden/)
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
