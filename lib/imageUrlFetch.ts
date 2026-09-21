/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns/promises'
import { type IncomingMessage } from 'node:http'
import https from 'node:https'
import net from 'node:net'

const MAX_REDIRECTS = 3
const SOCKET_TIMEOUT_MS = 5000
const TOTAL_TIMEOUT_MS = 15000

export const MAX_IMAGE_BYTES = 5 * 1024 * 1024

const IMAGE_CONTENT_TYPES: Record<string, string> = {
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

async function resolvePublicAddress (hostname: string) {
  if (net.isIP(hostname) !== 0) {
    if (addressBlocked(hostname)) throw new Error('url resolves to a non-public address')
    return { address: hostname, family: net.isIP(hostname) }
  }
  const resolved = await dns.lookup(hostname, { all: true, verbatim: true })
  const target = resolved[0]
  if (target === undefined || resolved.some(({ address }) => addressBlocked(address))) {
    throw new Error('url resolves to a non-public address')
  }
  return target
}

/* Connects to the address validated beforehand so that a DNS record changing between
   validation and connection cannot redirect the request to an internal host. */
async function requestImage (url: string, signal: AbortSignal): Promise<IncomingMessage> {
  const parsed = new URL(url)
  if (parsed.protocol !== 'https:') {
    throw new Error('only https urls are allowed for profile images')
  }
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '')
  const pinned = await resolvePublicAddress(hostname)
  return await new Promise<IncomingMessage>((resolve, reject) => {
    const request = https.request({
      hostname,
      port: parsed.port === '' ? 443 : Number(parsed.port),
      path: `${parsed.pathname}${parsed.search}`,
      timeout: SOCKET_TIMEOUT_MS,
      signal,
      lookup: (_hostname, options, callback) => {
        if (options.all === true) {
          callback(null, [{ address: pinned.address, family: pinned.family }])
          return
        }
        callback(null, pinned.address, pinned.family)
      }
    }, resolve)
    request.on('timeout', () => { request.destroy(new Error('timed out while retrieving the image')) })
    request.on('error', reject)
    request.end()
  })
}

export async function fetchProfileImage (url: string): Promise<{ stream: IncomingMessage, ext: string }> {
  const signal = AbortSignal.timeout(TOTAL_TIMEOUT_MS)
  let target = url
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    const response = await requestImage(target, signal)
    const status = response.statusCode ?? 0
    if (status >= 300 && status < 400) {
      response.destroy()
      const location = response.headers.location
      if (location === undefined) throw new Error('url returned a redirect without a location header')
      target = new URL(location, target).toString()
      continue
    }
    if (status < 200 || status >= 300) {
      response.destroy()
      throw new Error('url returned a non-OK status code')
    }
    const ext = IMAGE_CONTENT_TYPES[response.headers['content-type']?.split(';')[0].trim().toLowerCase() ?? '']
    if (ext === undefined) {
      response.destroy()
      throw new Error('url did not return a supported image content type')
    }
    if (Number(response.headers['content-length']) > MAX_IMAGE_BYTES) {
      response.destroy()
      throw new Error('image exceeds the maximum allowed size')
    }
    return { stream: response, ext }
  }
  throw new Error('url exceeded the maximum number of redirects')
}
