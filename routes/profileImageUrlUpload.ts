/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export const MAX_PROFILE_IMAGE_BYTES = 200000
const MAX_REDIRECTS = 3
const REQUEST_TIMEOUT_MS = 10000

const imageTypes = [
  { mediaTypes: ['image/jpeg', 'image/jpg', 'image/pjpeg'], extension: 'jpg', magic: [0xff, 0xd8, 0xff] },
  { mediaTypes: ['image/png'], extension: 'png', magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { mediaTypes: ['image/gif'], extension: 'gif', magic: [0x47, 0x49, 0x46, 0x38] }
]

const blockedIpv4 = new net.BlockList()
const blockedIpv6 = new net.BlockList()
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
] as const) blockedIpv4.addSubnet(address, prefix, 'ipv4')
for (const [address, prefix] of [
  ['::', 96], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23],
  ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]
] as const) blockedIpv6.addSubnet(address, prefix, 'ipv6')

export class ProfileImageFetchError extends Error {}

export function isPublicAddress (address: string) {
  const family = net.isIP(address)
  if (family === 4) return !blockedIpv4.check(address, 'ipv4')
  if (family === 6) return !blockedIpv6.check(address, 'ipv6')
  return false
}

function parseImageUrl (rawUrl: unknown, base?: URL) {
  if (typeof rawUrl !== 'string') throw new ProfileImageFetchError('image URL must be a string')
  let url: URL
  try {
    url = new URL(rawUrl, base)
  } catch {
    throw new ProfileImageFetchError('image URL is not a valid absolute URL')
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new ProfileImageFetchError('image URL must use http or https')
  if (url.username || url.password) throw new ProfileImageFetchError('image URL must not contain credentials')
  return url
}

function detectImageExtension (contentType: string, data: Buffer) {
  const mediaType = contentType.split(';')[0].trim().toLowerCase()
  const type = imageTypes.find(candidate => candidate.mediaTypes.includes(mediaType))
  if (!type) throw new ProfileImageFetchError('image URL must return a JPEG, PNG or GIF image')
  if (data.length < type.magic.length || type.magic.some((byte, i) => data[i] !== byte)) {
    throw new ProfileImageFetchError('image content does not match its content type')
  }
  return type.extension
}

type Fetched = { redirect: string } | { data: Buffer, extension: string }

function requestOnce (url: URL, isAllowedAddress: (address: string) => boolean): Promise<Fetched> {
  const host = url.hostname.replace(/^\[(.*)\]$/, '$1')
  if (net.isIP(host) !== 0 && !isAllowedAddress(host)) throw new ProfileImageFetchError('image host is not allowed')

  // Connect only to addresses that were checked, so DNS rebinding cannot swap in an internal IP
  const lookup = (hostname: string, options: dns.LookupOptions, callback: (...args: any[]) => void) => {
    dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) return callback(err)
      if (addresses.length === 0 || addresses.some(({ address }) => !isAllowedAddress(address))) {
        return callback(new ProfileImageFetchError('image host is not allowed'))
      }
      if (options.all) return callback(null, addresses)
      callback(null, addresses[0].address, addresses[0].family)
    })
  }

  const client = url.protocol === 'https:' ? https : http
  return new Promise<Fetched>((resolve, reject) => {
    const req = client.get(url, { agent: false, lookup, timeout: REQUEST_TIMEOUT_MS, headers: { accept: 'image/jpeg, image/png, image/gif', 'accept-encoding': 'identity' } }, (res) => {
      const fail = (message: string) => {
        res.destroy()
        reject(new ProfileImageFetchError(message))
      }
      const status = res.statusCode ?? 0
      if ([301, 302, 303, 307, 308].includes(status) && res.headers.location) {
        res.destroy()
        req.destroy()
        resolve({ redirect: res.headers.location })
        return
      }
      if (status !== 200) return fail(`image URL returned status ${status}`)
      const contentType = res.headers['content-type'] ?? ''
      if (!/^image\//i.test(contentType)) return fail('image URL did not return an image')
      if (Number(res.headers['content-length'] ?? 0) > MAX_PROFILE_IMAGE_BYTES) return fail('image is too large')
      const chunks: Buffer[] = []
      let size = 0
      res.on('data', (chunk: Buffer) => {
        size += chunk.length
        if (size > MAX_PROFILE_IMAGE_BYTES) return fail('image is too large')
        chunks.push(chunk)
      })
      res.on('end', () => {
        if (size > MAX_PROFILE_IMAGE_BYTES) return
        try {
          const data = Buffer.concat(chunks)
          resolve({ data, extension: detectImageExtension(contentType, data) })
        } catch (error) {
          reject(error)
        }
      })
      res.on('error', reject)
    })
    const deadline = setTimeout(() => { req.destroy(new ProfileImageFetchError('image request timed out')) }, REQUEST_TIMEOUT_MS)
    req.on('timeout', () => { req.destroy(new ProfileImageFetchError('image request timed out')) })
    req.on('error', reject)
    req.on('close', () => { clearTimeout(deadline) })
  })
}

export async function fetchProfileImage (rawUrl: unknown, isAllowedAddress: (address: string) => boolean = isPublicAddress) {
  let url = parseImageUrl(rawUrl)
  for (let redirects = 0; ; redirects++) {
    const result = await requestOnce(url, isAllowedAddress)
    if (!('redirect' in result)) return result
    if (redirects >= MAX_REDIRECTS) throw new ProfileImageFetchError('image URL redirected too many times')
    url = parseImageUrl(result.redirect, url)
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const image = await fetchProfileImage(url)
          const fileName = `${loggedInUser.data.id}.${image.extension}`
          await fs.promises.writeFile(`frontend/dist/frontend/assets/public/images/uploads/${fileName}`, image.data)
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${fileName}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
