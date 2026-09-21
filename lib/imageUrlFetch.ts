/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns/promises'
import net from 'node:net'

const MAX_REDIRECTS = 3
const FETCH_TIMEOUT_MS = 5000

export const MAX_IMAGE_BYTES = 5 * 1024 * 1024

export const IMAGE_CONTENT_TYPES: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'image/svg+xml': 'svg',
  'image/gif': 'gif'
}

function ipv4Blocked (address: string): boolean {
  const [a, b] = address.split('.').map(Number)
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19))
}

function ipv6Groups (address: string): number[] | undefined {
  let text = address.toLowerCase().split('%')[0]
  const embedded = /(\d+\.\d+\.\d+\.\d+)$/.exec(text)
  if (embedded !== null) {
    const octets = embedded[1].split('.').map(Number)
    text = text.slice(0, embedded.index) + ((octets[0] << 8) | octets[1]).toString(16) + ':' + ((octets[2] << 8) | octets[3]).toString(16)
  }
  const [head, tail] = text.split('::')
  const left = head === '' ? [] : head.split(':')
  const right = tail === undefined || tail === '' ? [] : tail.split(':')
  if (tail === undefined && left.length !== 8) return undefined
  const groups = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right].map((group) => parseInt(group, 16))
  return groups.length === 8 && groups.every((group) => Number.isInteger(group)) ? groups : undefined
}

function ipv6Blocked (address: string): boolean {
  const groups = ipv6Groups(address)
  if (groups === undefined) return true
  const embeddedIpv4 = [(groups[6] >> 8) & 0xff, groups[6] & 0xff, (groups[7] >> 8) & 0xff, groups[7] & 0xff].join('.')
  if (groups.slice(0, 5).every((group) => group === 0) && (groups[5] === 0xffff || groups[5] === 0)) {
    return groups[6] === 0 && groups[7] <= 1 ? true : ipv4Blocked(embeddedIpv4)
  }
  if (groups[0] === 0x64 && groups[1] === 0xff9b) return true
  return (groups[0] & 0xfe00) === 0xfc00 || (groups[0] & 0xffc0) === 0xfe80 || (groups[0] & 0xff00) === 0xff00
}

function addressBlocked (address: string): boolean {
  const family = net.isIP(address)
  if (family === 4) return ipv4Blocked(address)
  if (family === 6) return ipv6Blocked(address)
  return true
}

async function assertPubliclyRoutableHttpsUrl (url: string) {
  const parsed = new URL(url)
  if (parsed.protocol !== 'https:') {
    throw new Error('only https urls are allowed for profile images')
  }
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '')
  if (net.isIP(hostname) !== 0) {
    if (addressBlocked(hostname)) throw new Error('url resolves to a non-public address')
    return
  }
  const resolved = await dns.lookup(hostname, { all: true, verbatim: true })
  if (resolved.length === 0 || resolved.some(({ address }) => addressBlocked(address))) {
    throw new Error('url resolves to a non-public address')
  }
}

export async function fetchProfileImage (url: string): Promise<{ response: Response, ext: string }> {
  let target = url
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    await assertPubliclyRoutableHttpsUrl(target)
    const response = await fetch(target, { redirect: 'manual', signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location')
      if (location === null) throw new Error('url returned a redirect without a location header')
      await response.body?.cancel()
      target = new URL(location, target).toString()
      continue
    }
    if (!response.ok || !response.body) {
      throw new Error('url returned a non-OK status code or an empty body')
    }
    const ext = IMAGE_CONTENT_TYPES[response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() ?? '']
    if (ext === undefined) {
      await response.body.cancel()
      throw new Error('url did not return a supported image content type')
    }
    const length = Number(response.headers.get('content-length'))
    if (Number.isFinite(length) && length > MAX_IMAGE_BYTES) {
      await response.body.cancel()
      throw new Error('image exceeds the maximum allowed size')
    }
    return { response, ext }
  }
  throw new Error('url exceeded the maximum number of redirects')
}
