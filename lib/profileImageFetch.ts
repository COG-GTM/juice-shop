/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns, { type LookupAddress } from 'node:dns'
import http, { type IncomingMessage } from 'node:http'
import https from 'node:https'
import net, { type LookupFunction } from 'node:net'
import { pipeline, Transform, type Readable } from 'node:stream'

const MAX_REDIRECTS = 3
const MAX_BYTES = 5 * 1024 * 1024
const SOCKET_TIMEOUT_MS = 5000
const TOTAL_TIMEOUT_MS = 15000

const IMAGE_EXTENSIONS: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif'
}

const nonPublicIPv4 = new net.BlockList()
const nonPublicIPv6 = new net.BlockList()
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
] as const) {
  nonPublicIPv4.addSubnet(network, prefix, 'ipv4')
}
for (const [network, prefix] of [
  ['::', 96], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23],
  ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]
] as const) {
  nonPublicIPv6.addSubnet(network, prefix, 'ipv6')
}

export class ProfileImageUrlError extends Error {}

export interface ProfileImage {
  extension: string
  body: Readable
}

export interface ProfileImageFetchOptions {
  allowedHosts?: string[]
  allowedPorts?: string[]
  resolve?: (hostname: string) => Promise<LookupAddress[]>
  isAllowedAddress?: (address: string) => boolean
  timeoutMs?: number
}

export function isPublicAddress (address: string) {
  switch (net.isIP(address)) {
    case 4: return !nonPublicIPv4.check(address, 'ipv4')
    case 6: return !nonPublicIPv6.check(address, 'ipv6')
    default: return false
  }
}

export function allowedHostsFromEnv (value = process.env.PROFILE_IMAGE_ALLOWED_HOSTS) {
  return (value ?? '').split(',').map(host => host.trim().toLowerCase()).filter(host => host.length > 0)
}

async function defaultResolve (hostname: string) {
  return await dns.promises.lookup(hostname, { all: true, verbatim: true })
}

function parseUrl (rawUrl: string, base?: URL) {
  let url: URL
  try {
    url = new URL(rawUrl, base)
  } catch {
    throw new ProfileImageUrlError('invalid url')
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new ProfileImageUrlError('only http(s) urls are allowed')
  if (url.username !== '' || url.password !== '') throw new ProfileImageUrlError('urls with credentials are not allowed')
  return url
}

async function withDeadline<T> (promise: Promise<T>, signal: AbortSignal) {
  signal.throwIfAborted()
  let onAbort = () => {}
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => { reject(signal.reason) }
    signal.addEventListener('abort', onAbort, { once: true })
  })
  try {
    return await Promise.race([promise, aborted])
  } finally {
    signal.removeEventListener('abort', onAbort)
  }
}

async function resolveAllowedAddress (url: URL, options: ProfileImageFetchOptions, signal: AbortSignal) {
  const hostname = url.hostname.replace(/^\[(.*)\]$/, '$1').toLowerCase()
  const allowedHosts = options.allowedHosts ?? []
  if (allowedHosts.length > 0 && !allowedHosts.includes(hostname)) throw new ProfileImageUrlError('host is not allowed')
  if (!(options.allowedPorts ?? ['']).includes(url.port)) throw new ProfileImageUrlError('port is not allowed')

  const isAllowedAddress = options.isAllowedAddress ?? isPublicAddress
  const family = net.isIP(hostname)
  const addresses = family !== 0 ? [{ address: hostname, family }] : await withDeadline((options.resolve ?? defaultResolve)(hostname), signal)
  if (addresses.length === 0 || !addresses.every(({ address }) => isAllowedAddress(address))) {
    throw new ProfileImageUrlError('url resolves to a non-public address')
  }
  return addresses[0]
}

function pinnedLookup ({ address, family }: LookupAddress): LookupFunction {
  return (_hostname, options, callback) => {
    if (options.all === true) callback(null, [{ address, family }])
    else callback(null, address, family)
  }
}

async function get (url: URL, address: LookupAddress, signal: AbortSignal) {
  return await new Promise<IncomingMessage>((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http
    const request = transport.get(url, {
      agent: false,
      headers: { accept: Object.keys(IMAGE_EXTENSIONS).join(', ') },
      lookup: pinnedLookup(address),
      signal,
      timeout: SOCKET_TIMEOUT_MS
    }, resolve)
    request.on('timeout', () => request.destroy(new ProfileImageUrlError('image request timed out')))
    request.on('error', reject)
  })
}

function sizeLimit (maxBytes: number) {
  let received = 0
  return new Transform({
    transform (chunk: Buffer, _encoding, callback) {
      received += chunk.length
      if (received > maxBytes) callback(new ProfileImageUrlError('image is too large'))
      else callback(null, chunk)
    }
  })
}

export async function fetchProfileImage (rawUrl: string, options: ProfileImageFetchOptions = {}): Promise<ProfileImage> {
  const signal = AbortSignal.timeout(options.timeoutMs ?? TOTAL_TIMEOUT_MS)
  let url = parseUrl(rawUrl)
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const address = await resolveAllowedAddress(url, options, signal)
    const response = await get(url, address, signal)
    const status = response.statusCode ?? 0

    if (status >= 300 && status < 400 && response.headers.location !== undefined) {
      response.destroy()
      url = parseUrl(response.headers.location, url)
      continue
    }
    if (status !== 200) {
      response.destroy()
      throw new ProfileImageUrlError(`url returned status ${status}`)
    }
    const contentType = (response.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase()
    const extension = IMAGE_EXTENSIONS[contentType]
    if (extension === undefined) {
      response.destroy()
      throw new ProfileImageUrlError('url did not return a supported image type')
    }
    if (Number(response.headers['content-length'] ?? 0) > MAX_BYTES) {
      response.destroy()
      throw new ProfileImageUrlError('image is too large')
    }
    return { extension, body: pipeline(response, sizeLimit(MAX_BYTES), () => {}) }
  }
  throw new ProfileImageUrlError('too many redirects')
}
