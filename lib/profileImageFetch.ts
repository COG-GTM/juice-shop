/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'

export const MAX_PROFILE_IMAGE_BYTES = 1024 * 1024
export const PROFILE_IMAGE_TIMEOUT_MS = 10000

export class ProfileImageFetchError extends Error {}

export interface ProfileImage {
  data: Buffer
  extension: 'jpg' | 'png' | 'gif'
}

const imageTypes: Array<{ contentType: RegExp, extension: ProfileImage['extension'], magic: number[], isComplete: (data: Buffer) => boolean }> = [
  { contentType: /^image\/(jpeg|jpg|pjpeg)$/, extension: 'jpg', magic: [0xff, 0xd8, 0xff], isComplete: data => data.length > 4 && data[data.length - 2] === 0xff && data[data.length - 1] === 0xd9 },
  { contentType: /^image\/png$/, extension: 'png', magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], isComplete: data => data.length >= 8 + 25 + 12 && data.subarray(-8, -4).toString('latin1') === 'IEND' },
  { contentType: /^image\/gif$/, extension: 'gif', magic: [0x47, 0x49, 0x46, 0x38], isComplete: data => data.length > 13 && data[data.length - 1] === 0x3b }
]

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

function detectImageType (contentType: string, data: Buffer) {
  const mediaType = contentType.split(';')[0].trim().toLowerCase()
  const type = imageTypes.find(candidate => candidate.contentType.test(mediaType))
  if (!type) throw new ProfileImageFetchError('profile image must be a JPEG, PNG or GIF image')
  if (data.length < type.magic.length || type.magic.some((byte, i) => data[i] !== byte)) {
    throw new ProfileImageFetchError('profile image content does not match its content type')
  }
  if (!type.isComplete(data)) throw new ProfileImageFetchError('profile image is truncated')
  return type.extension
}

export async function fetchProfileImage (rawUrl: unknown, isAllowedAddress: (address: string) => boolean = isPublicAddress, timeoutMs = PROFILE_IMAGE_TIMEOUT_MS): Promise<ProfileImage> {
  const url = parseProfileImageUrl(rawUrl)
  const host = url.hostname.replace(/^\[(.*)\]$/, '$1')
  if (net.isIP(host) && !isAllowedAddress(host)) throw new ProfileImageFetchError('profile image host is not allowed')

  // Resolve once and connect to the vetted address, so DNS rebinding cannot swap in an internal IP.
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
  return await new Promise<ProfileImage>((resolve, reject) => {
    // Socket timeouts only catch idle connections; this bounds the whole download, so a trickling server cannot hold the request open.
    const deadline = setTimeout(() => { req.destroy(new ProfileImageFetchError('profile image request timed out')) }, timeoutMs)
    const succeed = (image: ProfileImage) => {
      clearTimeout(deadline)
      resolve(image)
    }
    const abort = (error: unknown) => {
      clearTimeout(deadline)
      reject(error)
    }
    const req = client.get(url, { agent: false, lookup, timeout: timeoutMs, headers: { accept: 'image/jpeg, image/png, image/gif', 'accept-encoding': 'identity' } }, (res) => {
      const fail = (message: string) => {
        res.destroy()
        abort(new ProfileImageFetchError(message))
      }
      if (res.statusCode !== 200) return fail(`profile image URL returned status ${res.statusCode}`)
      const contentType = res.headers['content-type'] ?? ''
      if (!/^image\//i.test(contentType)) return fail('profile image URL did not return an image')
      if (!/^(identity)?$/i.test(res.headers['content-encoding'] ?? '')) return fail('profile image URL returned an encoded body')
      if (Number(res.headers['content-length'] ?? 0) > MAX_PROFILE_IMAGE_BYTES) return fail('profile image is too large')
      const chunks: Buffer[] = []
      let size = 0
      let aborted = false
      res.on('data', (chunk: Buffer) => {
        if (aborted) return
        size += chunk.length
        if (size > MAX_PROFILE_IMAGE_BYTES) {
          aborted = true
          fail('profile image is too large')
          return
        }
        chunks.push(chunk)
      })
      res.on('end', () => {
        if (aborted) return
        const data = Buffer.concat(chunks)
        try {
          succeed({ data, extension: detectImageType(contentType, data) })
        } catch (error) {
          abort(error)
        }
      })
      res.on('error', abort)
    })
    req.on('timeout', () => req.destroy(new ProfileImageFetchError('profile image request timed out')))
    req.on('error', abort)
  })
}
