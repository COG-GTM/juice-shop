/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import { pipeline } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const MAX_REDIRECTS = 3
const REQUEST_TIMEOUT_MS = 10000

const blockedAddresses = new net.BlockList()
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3]
] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv4')
}
for (const [network, prefix] of [
  ['::', 128], ['::1', 128], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001:db8::', 32],
  ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]
] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv6')
}

export function isBlockedAddress (address: string): boolean {
  const family = net.isIP(address)
  if (family === 0) return true
  return blockedAddresses.check(address, family === 6 ? 'ipv6' : 'ipv4')
}

// Validates the addresses at connect time so DNS rebinding cannot swap in an internal host after a check
const safeLookup: net.LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) {
      callback(err, '', 0)
      return
    }
    if (addresses.length === 0 || addresses.some(({ address }) => isBlockedAddress(address))) {
      callback(new Error(`Blocked request to disallowed host ${hostname}`), '', 0)
      return
    }
    if (options.all) {
      (callback as unknown as (err: null, addresses: dns.LookupAddress[]) => void)(null, addresses)
    } else {
      callback(null, addresses[0].address, addresses[0].family)
    }
  })
}

export function parseAllowedUrl (rawUrl: string): URL {
  const url = new URL(rawUrl)
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`Blocked request with disallowed protocol ${url.protocol}`)
  }
  if (url.username || url.password) {
    throw new Error('Blocked request with embedded credentials')
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '')
  if (net.isIP(hostname) !== 0 && isBlockedAddress(hostname)) {
    throw new Error(`Blocked request to disallowed host ${hostname}`)
  }
  return url
}

export async function fetchExternalImage (rawUrl: string, redirectsLeft = MAX_REDIRECTS): Promise<http.IncomingMessage> {
  const url = parseAllowedUrl(rawUrl)
  const client = url.protocol === 'https:' ? https : http
  const response = await new Promise<http.IncomingMessage>((resolve, reject) => {
    const request = client.get(url, { lookup: safeLookup, timeout: REQUEST_TIMEOUT_MS }, resolve)
    request.on('timeout', () => request.destroy(new Error('Request timed out')))
    request.on('error', reject)
  })
  const status = response.statusCode ?? 0
  if (status >= 300 && status < 400 && response.headers.location) {
    response.resume()
    if (redirectsLeft <= 0) throw new Error('Too many redirects')
    return await fetchExternalImage(new URL(response.headers.location, url).toString(), redirectsLeft - 1)
  }
  if (status < 200 || status >= 300) {
    response.resume()
    throw new Error('url returned a non-OK status code or an empty body')
  }
  return response
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetchExternalImage(url)
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await pipeline(response, fileStream)
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
