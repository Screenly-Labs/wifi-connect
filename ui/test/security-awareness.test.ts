/**
 * Behaviour of the network-dependent form fields, run against the real
 * portal markup in a DOM.
 *
 * The risky case is switching networks: a username left in the hidden
 * enterprise block would still submit, and the server reads a username as
 * "join over 802.1X", so a WPA-PSK join would go out as an EAP login.
 */

import { GlobalRegistrator } from '@happy-dom/global-registrator'
import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = join(dirname(fileURLToPath(import.meta.url)), '..', 'src')

const radio = (hex: string, pw: boolean, id: boolean): string =>
  `<input type="radio" name="ssid_hex" value="${hex}" ` +
  `data-needs-passphrase="${pw}" data-needs-identity="${id}">`

beforeAll(async () => {
  GlobalRegistrator.register()
  const page = readFileSync(join(src, 'index.html'), 'utf8')
  const body = page.match(/<body>([\s\S]*)<\/body>/)?.[1] ?? ''
  document.body.innerHTML = body.replace(
    '{{NETWORKS}}',
    radio('436f7270', false, true) + radio('486f6d65', true, false),
  )
  await import('../src/portal.ts')
})

afterAll(async () => {
  await GlobalRegistrator.unregister()
})

const input = (id: string): HTMLInputElement => document.getElementById(id) as HTMLInputElement

function pick(hex: string): void {
  const r = document.querySelector(`input[value="${hex}"]`) as HTMLInputElement
  r.checked = true
  r.dispatchEvent(new Event('change'))
}

/** What the browser would POST: named, enabled controls only. */
function submitted(): Record<string, string> {
  const form = document.querySelector('form') as HTMLFormElement
  return Object.fromEntries(
    [...new FormData(form).entries()].map(([k, v]) => [k, String(v)] as [string, string]),
  )
}

describe('switching between enterprise and PSK networks', () => {
  test('enterprise shows the username block and lifts the WPA length limits', () => {
    pick('436f7270')
    expect((document.getElementById('identity-field') as HTMLElement).hidden).toBe(false)
    expect(input('identity').disabled).toBe(false)
    expect(input('server-domain').disabled).toBe(false)
    expect(input('pw').hasAttribute('maxlength')).toBe(false)
    expect(input('pw').hasAttribute('minlength')).toBe(false)
    expect(document.getElementById('pw-hint')?.textContent).not.toMatch(/63/)
  })

  test('a username typed for enterprise is not submitted with a PSK network', () => {
    pick('436f7270')
    input('identity').value = 'alice'
    input('server-domain').value = 'radius.example.com'
    pick('486f6d65')
    input('pw').value = 'abcdefgh'

    const posted = submitted()
    expect(posted.identity ?? '').toBe('')
    expect(posted.server_domain ?? '').toBe('')
    expect(posted.passphrase).toBe('abcdefgh')
    expect(input('pw').getAttribute('maxlength')).toBe('63')
    expect(input('pw').getAttribute('minlength')).toBe('8')
    expect(document.getElementById('pw-hint')?.textContent).toMatch(/8 to 63/)
  })

  test('the sign-in method is posted for enterprise and nothing else', () => {
    const method = document.getElementById('eap-method') as HTMLSelectElement
    pick('436f7270')
    expect(method.disabled).toBe(false)
    expect(submitted().eap_method).toBe('peap')
    method.value = 'ttls-pap'
    expect(submitted().eap_method).toBe('ttls-pap')

    // Disabled is what keeps it out of the POST. happy-dom's FormData still
    // lists a disabled <select> (browsers do not), so assert the cause.
    pick('486f6d65')
    expect(method.disabled).toBe(true)

    // The next enterprise network starts from the default again.
    pick('436f7270')
    expect(submitted().eap_method).toBe('peap')
  })

  test('switching back to enterprise re-enables the username', () => {
    pick('436f7270')
    input('identity').value = 'alice'
    expect(submitted().identity).toBe('alice')
  })
})
