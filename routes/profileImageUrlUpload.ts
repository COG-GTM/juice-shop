/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns'
import http, { type IncomingMessage } from 'node:http'
import https from 'node:https'
import net from 'node:net'
import { Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import zlib from 'node:zlib'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const MAX_REDIRECTS = 5
const REQUEST_TIMEOUT_MS = 10000
const MAX_IMAGE_BYTES = 10 * 1024 * 1024

const blockedAddresses = new net.BlockList()
for (const [network, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4]] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv4')
}
for (const [network, prefix] of [['::', 128], ['::1', 128], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['2001::', 32], ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv6')
}

export function isBlockedAddress (address: string) {
  const family = net.isIP(address)
  if (family === 0) return true
  return blockedAddresses.check(address, family === 4 ? 'ipv4' : 'ipv6')
}

// Validates resolved addresses at connect time so DNS rebinding cannot bypass the check
const safeLookup: net.LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) {
      callback(err, '', 0)
      return
    }
    if (addresses.length === 0 || addresses.some(({ address }) => isBlockedAddress(address))) {
      callback(new Error(`Blocked request to disallowed address for host ${hostname}`), '', 0)
      return
    }
    if (options.all) {
      (callback as unknown as (err: null, addresses: dns.LookupAddress[]) => void)(null, addresses)
    } else {
      callback(null, addresses[0].address, addresses[0].family)
    }
  })
}

export async function fetchImage (rawUrl: string, redirectsLeft = MAX_REDIRECTS): Promise<IncomingMessage> {
  const url = new URL(rawUrl)
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`Blocked request with disallowed protocol ${url.protocol}`)
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '')
  if (net.isIP(hostname) !== 0 && isBlockedAddress(hostname)) {
    throw new Error(`Blocked request to disallowed address ${hostname}`)
  }
  const client = url.protocol === 'https:' ? https : http
  return await new Promise<IncomingMessage>((resolve, reject) => {
    const request = client.get(url, { lookup: safeLookup, timeout: REQUEST_TIMEOUT_MS, headers: { 'accept-encoding': 'gzip, deflate, br' } }, (response) => {
      const { statusCode = 0, headers } = response
      if (statusCode >= 300 && statusCode < 400 && headers.location) {
        response.resume()
        if (redirectsLeft <= 0) {
          reject(new Error('Too many redirects'))
          return
        }
        let redirectUrl: string
        try {
          redirectUrl = new URL(headers.location, url).toString()
        } catch (err) {
          reject(err)
          return
        }
        fetchImage(redirectUrl, redirectsLeft - 1).then(resolve, reject)
        return
      }
      resolve(response)
    })
    request.on('timeout', () => { request.destroy(new Error('Request timed out')) })
    request.on('error', reject)
  })
}

function contentDecoder (response: IncomingMessage): Transform[] {
  switch (response.headers['content-encoding']?.trim().toLowerCase()) {
    case 'gzip':
    case 'x-gzip':
      return [zlib.createGunzip()]
    case 'deflate':
      return [zlib.createInflate()]
    case 'br':
      return [zlib.createBrotliDecompress()]
    default:
      return []
  }
}

function sizeLimit (maxBytes: number) {
  let total = 0
  return new Transform({
    transform (chunk: Buffer, _encoding, callback) {
      total += chunk.length
      callback(total > maxBytes ? new Error(`Image exceeds ${maxBytes} bytes`) : null, chunk)
    }
  })
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetchImage(url)
          if (response.statusCode === undefined || response.statusCode < 200 || response.statusCode >= 300) {
            response.resume()
            throw new Error('url returned a non-OK status code')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await pipeline([response, ...contentDecoder(response), sizeLimit(MAX_IMAGE_BYTES), fileStream])
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
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
