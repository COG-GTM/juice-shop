/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'

export const MAX_PROFILE_IMAGE_BYTES = 200000
const TIMEOUT_MS = 10000

export class ProfileImageFetchError extends Error {}

const blockedIpv4Ranges = new net.BlockList()
const blockedIpv6Ranges = new net.BlockList()
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
] as const) blockedIpv4Ranges.addSubnet(address, prefix, 'ipv4')
for (const [address, prefix] of [
  ['::', 96], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23],
  ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]
] as const) blockedIpv6Ranges.addSubnet(address, prefix, 'ipv6')

export function isPublicAddress (address: string) {
  const family = net.isIP(address)
  if (family === 4) return !blockedIpv4Ranges.check(address, 'ipv4')
  if (family === 6) return !blockedIpv6Ranges.check(address, 'ipv6')
  return false
}

export function parseProfileImageUrl (rawUrl: unknown) {
  let url: URL
  try {
    url = new URL(String(rawUrl))
  } catch {
    throw new ProfileImageFetchError('profile image URL is not a valid absolute URL')
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new ProfileImageFetchError('profile image URL must use http or https')
  if (url.username || url.password) throw new ProfileImageFetchError('profile image URL must not contain credentials')
  return url
}

export async function fetchProfileImage (rawUrl: unknown, isAllowedAddress: (address: string) => boolean = isPublicAddress): Promise<Buffer> {
  const url = parseProfileImageUrl(rawUrl)
  const host = url.hostname.replace(/^\[(.*)\]$/, '$1')
  if (net.isIP(host) && !isAllowedAddress(host)) throw new ProfileImageFetchError('profile image host is not allowed')

  const lookup = (hostname: string, options: dns.LookupOptions, callback: (...args: any[]) => void) => {
    dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) return callback(err)
      if (addresses.length === 0 || addresses.some(({ address }) => !isAllowedAddress(address))) {
        return callback(new ProfileImageFetchError('profile image host is not allowed'))
      }
      if (options.all) return callback(null, addresses)
      callback(null, addresses[0].address, addresses[0].family)
    })
  }

  const client = url.protocol === 'https:' ? https : http
  return await new Promise<Buffer>((resolve, reject) => {
    const req = client.get(url, { agent: false, lookup, timeout: TIMEOUT_MS, headers: { accept: 'image/*', 'accept-encoding': 'identity' } }, (res) => {
      const fail = (message: string) => {
        res.destroy()
        reject(new ProfileImageFetchError(message))
      }
      if (res.statusCode !== 200) return fail(`profile image URL returned status ${res.statusCode}`)
      if (!/^image\//i.test(res.headers['content-type'] ?? '')) return fail('profile image URL did not return an image')
      if (!/^(identity)?$/i.test(res.headers['content-encoding'] ?? '')) return fail('profile image URL returned an encoded body')
      if (Number(res.headers['content-length'] ?? 0) > MAX_PROFILE_IMAGE_BYTES) return fail('profile image is too large')
      const chunks: Buffer[] = []
      let size = 0
      res.on('data', (chunk: Buffer) => {
        size += chunk.length
        if (size > MAX_PROFILE_IMAGE_BYTES) return fail('profile image is too large')
        chunks.push(chunk)
      })
      res.on('end', () => {
        if (size === 0) return reject(new ProfileImageFetchError('profile image URL returned an empty body'))
        resolve(Buffer.concat(chunks))
      })
      res.on('error', reject)
    })
    req.on('timeout', () => req.destroy(new ProfileImageFetchError('profile image request timed out')))
    req.on('error', reject)
  })
}
