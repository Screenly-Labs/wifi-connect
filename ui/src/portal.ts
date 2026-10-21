/**
 * Portal enhancement.
 *
 * Everything here is strictly additive. The page is a working `<form>` that
 * posts to /connect with JavaScript disabled; this file only makes it nicer.
 * If any of it throws, the form still submits.
 *
 * Two environment constraints shape the code:
 *
 *  - iOS's Captive Network Assistant has no localStorage and *throws* a
 *    SecurityError on access rather than returning null. Every storage call
 *    is therefore wrapped, and a failure degrades to a session-only theme
 *    toggle rather than killing the script.
 *  - While a join is in flight the access point is down, so fetches fail.
 *    That is the EXPECTED path, not an error, and must never be rendered as
 *    one.
 */

interface PortalStatus {
  state: 'portal' | 'joining' | 'failed' | 'connected'
  ssid?: string
  error?: string
  attempts?: number
}

function writeStored(key: string, value: string): void {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* Session-only. prefers-color-scheme still carries the default. */
  }
}

function resolvedTheme(): 'light' | 'dark' {
  const explicit = document.documentElement.getAttribute('data-theme')
  if (explicit === 'light' || explicit === 'dark') return explicit
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function initThemeToggle(): void {
  const button = document.getElementById('theme-toggle')
  if (!(button instanceof HTMLButtonElement)) return

  button.hidden = false
  button.addEventListener('click', () => {
    const next = resolvedTheme() === 'dark' ? 'light' : 'dark'
    document.documentElement.setAttribute('data-theme', next)
    writeStored('wc-theme', next)
  })
}

function initPasswordToggle(): void {
  const toggle = document.getElementById('pw-toggle')
  const input = document.getElementById('pw')
  if (!(toggle instanceof HTMLButtonElement) || !(input instanceof HTMLInputElement)) return

  toggle.hidden = false
  toggle.addEventListener('click', () => {
    const revealed = input.type === 'text'
    input.type = revealed ? 'password' : 'text'
    toggle.textContent = revealed ? 'Show' : 'Hide'
    toggle.setAttribute('aria-pressed', String(!revealed))
    input.focus()
  })
}

/**
 * Open networks take no password, and enterprise ones also need a username.
 * Reflecting that as the user picks a network avoids submitting a
 * credential the network cannot accept.
 */
function initSecurityAwareness(): void {
  const password = document.getElementById('pw')
  const identityField = document.getElementById('identity-field')
  const hint = document.getElementById('pw-hint')
  if (!(password instanceof HTMLInputElement)) return
  // The markup's hint states the WPA-PSK rule, which is right without
  // JavaScript (no enterprise sign-in is possible then). Keep it to restore.
  const pskHint = hint?.textContent ?? ''

  const apply = (radio: HTMLInputElement): void => {
    // Server-rendered booleans, decided once in nm::security. Re-deriving
    // them from the slug here would be a second copy of that rule, and the
    // two would drift - OWE is encrypted but takes no password, which a
    // naive check gets wrong.
    const needsPassphrase = radio.dataset.needsPassphrase !== 'false'
    const needsIdentity = radio.dataset.needsIdentity === 'true'
    // Enterprise (PEAP/TTLS) takes no WPA passphrase but still needs a
    // password alongside the identity, so the field is required whenever
    // either is true. Disabling it for enterprise would leave the password
    // unsubmitted and the join would silently fall back to open and fail.
    const needsPassword = needsPassphrase || needsIdentity

    password.disabled = !needsPassword
    password.required = false
    if (!needsPassword) password.value = ''
    // The 8-character floor is a WPA-PSK rule; EAP passwords have no such
    // minimum, and on a disabled/empty field it would block submission of an
    // open network. Apply it only to PSK networks.
    // Likewise the 63-character ceiling: directory passwords behind an
    // 802.1X network are routinely longer, and maxlength silently truncates
    // what a password manager pastes.
    if (needsPassphrase) {
      password.setAttribute('minlength', '8')
      password.setAttribute('maxlength', '63')
    } else {
      password.removeAttribute('minlength')
      password.removeAttribute('maxlength')
    }
    // Telling an enterprise user their directory password must be 8 to 63
    // characters is wrong, and sends them looking for a different one.
    if (hint) hint.textContent = needsIdentity ? 'Your enterprise (802.1X) password.' : pskHint
    if (identityField instanceof HTMLElement) identityField.hidden = !needsIdentity
    // A hidden input still submits, and a username is what makes the server
    // join over 802.1X. So when the enterprise block hides, clear AND
    // disable its inputs (disabled inputs are not submitted): a username
    // typed for one network must not turn a PSK join into an EAP one. The
    // server drops it for a scanned non-enterprise network too.
    for (const id of ['identity', 'server-domain']) {
      const input = document.getElementById(id)
      if (!(input instanceof HTMLInputElement)) continue
      input.disabled = !needsIdentity
      if (!needsIdentity) input.value = ''
    }
  }

  for (const el of document.querySelectorAll('input[name="ssid_hex"]')) {
    if (!(el instanceof HTMLInputElement)) continue
    el.addEventListener('change', () => apply(el))
    if (el.checked) apply(el)
  }
}

/**
 * Poll /api/status from the connecting page.
 *
 * A failed fetch is the normal case here: the access point is down while
 * NetworkManager attempts the join. Keep quiet and keep retrying.
 */
function initStatusPolling(): void {
  const text = document.getElementById('status-text')
  if (!(text instanceof HTMLElement)) return

  const poll = async (): Promise<void> => {
    try {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 3000)
      const response = await fetch('/api/status', {
        signal: controller.signal,
        cache: 'no-store',
      })
      clearTimeout(timer)
      if (!response.ok) return

      const status = (await response.json()) as PortalStatus
      if (status.state === 'failed' && status.error) {
        text.textContent = status.error
        document.getElementById('status')?.setAttribute('role', 'alert')
      } else if (status.state === 'connected') {
        text.textContent = `Connected to ${status.ssid ?? 'the network'}.`
      }
    } catch {
      /* Expected while the AP is down. */
    }
  }

  void poll()
  setInterval(() => void poll(), 2000)
}

function main(): void {
  initThemeToggle()
  initPasswordToggle()
  initSecurityAwareness()
  initStatusPolling()
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', main)
} else {
  main()
}
