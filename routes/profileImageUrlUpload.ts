/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import dns, { type LookupAddress, type LookupOptions } from 'node:dns'
import https from 'node:https'
import net from 'node:net'
import { type Request, type Response, type NextFunction } from 'express'
import fileType from 'file-type'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const MAX_URL_LENGTH = 2048
const MAX_IMAGE_BYTES = 5 * 1024 * 1024
const DOWNLOAD_TIMEOUT_MS = 10000
const ALLOWED_IMAGE_TYPES: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'image/webp': 'webp'
}

const blockedAddresses = new net.BlockList()
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv4')
}
for (const [network, prefix] of [
  ['::', 96], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64],
  ['2001:db8::', 32], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]
] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv6')
}

export function isBlockedAddress (address: string) {
  const family = net.isIP(address)
  if (family === 0) return true
  return blockedAddresses.check(address, family === 6 ? 'ipv6' : 'ipv4')
}

function publicOnlyLookup (hostname: string, options: LookupOptions, callback: (...args: any[]) => void) {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses: LookupAddress[]) => {
    if (err) {
      callback(err)
      return
    }
    if (addresses.length === 0 || addresses.some(({ address }) => isBlockedAddress(address))) {
      callback(new Error(`Image host ${hostname} resolves to a non-public address`))
      return
    }
    if (options.all) {
      callback(null, addresses)
    } else {
      callback(null, addresses[0].address, addresses[0].family)
    }
  })
}

export function parseImageUrl (imageUrl: unknown) {
  if (typeof imageUrl !== 'string' || imageUrl.length > MAX_URL_LENGTH) return null
  let url: URL
  try {
    url = new URL(imageUrl)
  } catch {
    return null
  }
  if (url.protocol !== 'https:' || url.port !== '' || url.username !== '' || url.password !== '') return null
  const hostname = url.hostname.replace(/^\[(.*)\]$/, '$1')
  if (net.isIP(hostname) !== 0 && isBlockedAddress(hostname)) return null
  return url
}

function downloadImage (url: URL) {
  return new Promise<Buffer>((resolve, reject) => {
    const request = https.get(url, { lookup: publicOnlyLookup as any, headers: { accept: Object.keys(ALLOWED_IMAGE_TYPES).join(', ') } }, (response) => {
      const contentType = (response.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase()
      if (response.statusCode !== 200 || ALLOWED_IMAGE_TYPES[contentType] === undefined) {
        request.destroy(new Error(`Image URL returned status ${response.statusCode} with content type "${contentType}"`))
        return
      }
      if (Number(response.headers['content-length'] ?? 0) > MAX_IMAGE_BYTES) {
        request.destroy(new Error('Image is too large'))
        return
      }
      const chunks: Buffer[] = []
      let size = 0
      response.on('data', (chunk: Buffer) => {
        size += chunk.length
        if (size > MAX_IMAGE_BYTES) {
          request.destroy(new Error('Image is too large'))
          return
        }
        chunks.push(chunk)
      })
      response.on('end', () => { resolve(Buffer.concat(chunks)) })
      response.on('error', reject)
    })
    const timer = setTimeout(() => request.destroy(new Error('Image download timed out')), DOWNLOAD_TIMEOUT_MS)
    request.on('close', () => { clearTimeout(timer) })
    request.on('error', reject)
  })
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (!loggedInUser) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
      const imageUrl = req.body.imageUrl
      if (typeof imageUrl === 'string' && imageUrl.length <= MAX_URL_LENGTH && imageUrl.includes('solve/challenges/server-side')) req.app.locals.abused_ssrf_bug = true
      const url = parseImageUrl(imageUrl)
      if (url === null) {
        res.status(400)
        next(new Error('Image URL must be a public https:// address of at most ' + MAX_URL_LENGTH + ' characters'))
        return
      }
      let ext: string
      try {
        const buffer = await downloadImage(url)
        const detectedType = await fileType.fromBuffer(buffer)
        if (detectedType === undefined || ALLOWED_IMAGE_TYPES[detectedType.mime] === undefined) {
          throw new Error('downloaded file is not a JPEG, PNG, GIF or WebP image')
        }
        ext = ALLOWED_IMAGE_TYPES[detectedType.mime]
        await fs.writeFile(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, buffer)
      } catch (error) {
        logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}`)
        res.status(422)
        next(new Error('Could not retrieve a valid image from the given URL'))
        return
      }
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
      } catch (error) {
        next(error)
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
