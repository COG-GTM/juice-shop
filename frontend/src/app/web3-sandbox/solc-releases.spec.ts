/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { afterEach, describe, expect, it, vi } from 'vitest'
import { SOLC_BINARIES_BASE_URL, SOLC_RELEASES, fetchVerifiedSolcBundle } from './solc-releases'

const payload = new TextEncoder().encode('abc')
const payloadSha256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
const otherSha256 = '0f7a4e1c9e6b2d7ce6ceb3c53d24b7f5f4e0b3f1c2d6c4d15d3a3b6dfbbfc0ce'

describe('fetchVerifiedSolcBundle', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('pins every selectable compiler to a SHA-256 digest', () => {
    for (const release of SOLC_RELEASES) {
      expect(release.sha256).toMatch(/^[0-9a-f]{64}$/)
    }
  })

  it('returns an object URL when the downloaded bundle matches the pinned digest', async () => {
    const release = { version: '0.0.0', file: 'soljson-test.js', sha256: payloadSha256 }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(payload, { status: 200 }))
    const createObjectURL = vi.fn().mockReturnValue('blob:verified')
    vi.stubGlobal('URL', Object.assign(Object.create(URL), URL, { createObjectURL }))

    await expect(fetchVerifiedSolcBundle(release)).resolves.toBe('blob:verified')
    expect(fetchSpy).toHaveBeenCalledWith(SOLC_BINARIES_BASE_URL + release.file)
    expect(createObjectURL).toHaveBeenCalledTimes(1)
    vi.unstubAllGlobals()
  })

  it('verifies the digest without SubtleCrypto (insecure HTTP contexts)', async () => {
    const release = { version: '0.0.0', file: 'soljson-test.js', sha256: payloadSha256 }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(payload, { status: 200 }))
    vi.stubGlobal('crypto', { subtle: undefined })
    vi.stubGlobal('URL', Object.assign(Object.create(URL), URL, { createObjectURL: vi.fn().mockReturnValue('blob:verified') }))

    await expect(fetchVerifiedSolcBundle(release)).resolves.toBe('blob:verified')
    vi.unstubAllGlobals()
  })

  it('rejects a bundle whose digest does not match the pinned value', async () => {
    const release = { version: '0.0.0', file: 'soljson-test.js', sha256: otherSha256 }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(payload, { status: 200 }))
    const createObjectURL = vi.fn()
    vi.stubGlobal('URL', Object.assign(Object.create(URL), URL, { createObjectURL }))

    await expect(fetchVerifiedSolcBundle(release)).rejects.toThrow('Integrity check failed')
    expect(createObjectURL).not.toHaveBeenCalled()
    vi.unstubAllGlobals()
  })

  it('rejects when the download fails', async () => {
    const release = SOLC_RELEASES[0]
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 503 }))

    await expect(fetchVerifiedSolcBundle(release)).rejects.toThrow('HTTP 503')
  })
})
