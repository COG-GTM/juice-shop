/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable, Transform } from 'node:stream'

const ALLOWED_PROTOCOLS = ['http:', 'https:']
const ALLOWED_PORTS = ['', '80', '443']
const MAX_REDIRECTS = 3
const REQUEST_TIMEOUT_MS = 5000

export const MAX_IMAGE_SIZE_BYTES = 2 * 1024 * 1024

const EXTENSION_BY_MIME_TYPE: Record<string, string | undefined> = {
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'image/svg+xml': 'svg'
}

export class UnsafeImageUrlError extends Error {}

const isPrivateIpv4 = (address: string) => {
  const [a, b] = address.split('.').map(Number)
  if (a === 0 || a === 10 || a === 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 192 && b === 0) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 198 && (b === 18 || b === 19)) return true
  if (a >= 224) return true
  return false
}

const isPrivateIpv6 = (address: string) => {
  const normalized = address.toLowerCase().split('%')[0]
  if (normalized === '::' || normalized === '::1') return true
  const mappedIpv4 = /^(?:::ffff:)([\d.]+)$/.exec(normalized)
  if (mappedIpv4 !== null && net.isIPv4(mappedIpv4[1])) return isPrivateIpv4(mappedIpv4[1])
  if (/^f[cd]/.test(normalized)) return true
  if (/^fe[89ab]/.test(normalized)) return true
  return false
}

export const isPrivateAddress = (address: string) => {
  if (net.isIPv4(address)) return isPrivateIpv4(address)
  if (net.isIPv6(address)) return isPrivateIpv6(address)
  return true
}

export const validateImageUrl = async (candidate: string) => {
  let url: URL
  try {
    url = new URL(candidate)
  } catch {
    throw new UnsafeImageUrlError('image url is not a valid absolute url')
  }
  if (!ALLOWED_PROTOCOLS.includes(url.protocol)) {
    throw new UnsafeImageUrlError(`image url protocol ${url.protocol} is not allowed`)
  }
  if (url.username !== '' || url.password !== '') {
    throw new UnsafeImageUrlError('image url must not contain credentials')
  }
  if (!ALLOWED_PORTS.includes(url.port)) {
    throw new UnsafeImageUrlError(`image url port ${url.port} is not allowed`)
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '')
  if (hostname === '') {
    throw new UnsafeImageUrlError('image url has no hostname')
  }
  if (net.isIP(hostname) !== 0) {
    if (isPrivateAddress(hostname)) {
      throw new UnsafeImageUrlError('image url resolves to a non-public address')
    }
    return url
  }
  let addresses: Array<{ address: string }>
  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true })
  } catch {
    throw new UnsafeImageUrlError(`image url hostname ${hostname} could not be resolved`)
  }
  if (addresses.length === 0 || addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new UnsafeImageUrlError('image url resolves to a non-public address')
  }
  return url
}

export const sizeLimitedStream = (maxBytes: number) => {
  let transferred = 0
  return new Transform({
    transform (chunk, _encoding, callback) {
      transferred += chunk.length
      if (transferred > maxBytes) {
        callback(new Error(`image exceeds the maximum size of ${maxBytes} bytes`))
        return
      }
      callback(null, chunk)
    }
  })
}

export const fetchImage = async (candidate: string) => {
  let target = await validateImageUrl(candidate)
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const response = await fetch(target, {
      redirect: 'manual',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    })
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location')
      await response.body?.cancel()
      if (location === null) {
        throw new UnsafeImageUrlError('image url redirect without location header')
      }
      target = await validateImageUrl(new URL(location, target).href)
      continue
    }
    if (!response.ok || !response.body) {
      throw new Error('url returned a non-OK status code or an empty body')
    }
    const mimeType = (response.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase()
    const ext = EXTENSION_BY_MIME_TYPE[mimeType]
    if (ext === undefined) {
      await response.body.cancel()
      throw new UnsafeImageUrlError(`content type ${mimeType} is not a supported image type`)
    }
    const contentLength = Number(response.headers.get('content-length'))
    if (Number.isFinite(contentLength) && contentLength > MAX_IMAGE_SIZE_BYTES) {
      await response.body.cancel()
      throw new Error(`image exceeds the maximum size of ${MAX_IMAGE_SIZE_BYTES} bytes`)
    }
    return {
      ext,
      stream: Readable.fromWeb(response.body as any).pipe(sizeLimitedStream(MAX_IMAGE_SIZE_BYTES))
    }
  }
  throw new UnsafeImageUrlError('image url exceeded the maximum number of redirects')
}
