/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'

export const PROFILE_IMAGE_TIMEOUT_MS = 10000

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
  if (typeof rawUrl !== 'string') throw new ProfileImageFetchError('profile image URL must be a string')
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    throw new ProfileImageFetchError('profile image URL is not a valid absolute URL')
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new ProfileImageFetchError('profile image URL must use http or https')
  if (url.username || url.password) throw new ProfileImageFetchError('profile image URL must not contain credentials')
  return url
}

function publicOnlyLookup (isAllowedAddress: (address: string) => boolean): net.LookupFunction {
  return (hostname, options, callback) => {
    dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) {
        callback(err, '', 0)
      } else if (addresses.length === 0 || addresses.some(({ address }) => !isAllowedAddress(address))) {
        callback(new ProfileImageFetchError('profile image host resolves to a non-public address'), '', 0)
      } else if (options.all) {
        (callback as unknown as (err: null, addresses: dns.LookupAddress[]) => void)(null, addresses)
      } else {
        callback(null, addresses[0].address, addresses[0].family)
      }
    })
  }
}

// Every address is vetted inside the socket's own DNS lookup (no rebinding window) and redirects are never followed.
export async function fetchProfileImage (rawUrl: unknown, isAllowedAddress: (address: string) => boolean = isPublicAddress, timeoutMs = PROFILE_IMAGE_TIMEOUT_MS) {
  const url = parseProfileImageUrl(rawUrl)
  const hostname = url.hostname.replace(/^\[(.*)\]$/, '$1')
  if (net.isIP(hostname) && !isAllowedAddress(hostname)) throw new ProfileImageFetchError('profile image host is a non-public address')
  const secure = url.protocol === 'https:'
  return await new Promise<http.IncomingMessage>((resolve, reject) => {
    const req = (secure ? https : http).get(url, {
      headers: { accept: 'image/*', 'accept-encoding': 'identity' },
      lookup: publicOnlyLookup(isAllowedAddress),
      agent: false,
      timeout: timeoutMs
    }, (res) => {
      clearTimeout(responseTimer)
      const encoding = res.headers['content-encoding']
      if (res.statusCode !== 200 || (encoding !== undefined && encoding !== 'identity')) {
        res.resume()
        reject(new ProfileImageFetchError(`profile image URL returned status ${res.statusCode} with content encoding ${encoding ?? 'identity'}`))
        return
      }
      resolve(res)
    })
    const responseTimer = setTimeout(() => req.destroy(new ProfileImageFetchError('profile image request timed out')), timeoutMs)
    req.on('timeout', () => req.destroy(new ProfileImageFetchError('profile image request timed out')))
    req.on('error', (error) => {
      clearTimeout(responseTimer)
      reject(error)
    })
  })
}
