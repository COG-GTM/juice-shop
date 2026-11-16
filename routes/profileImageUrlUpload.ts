/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const FETCH_TIMEOUT_MS = 10000

const blockedAddresses = new net.BlockList()
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv4')
}
// IPv4-mapped addresses are matched against the IPv4 subnets above; NAT64 and 6to4 can embed internal IPv4 addresses too
for (const [network, prefix] of [
  ['::', 127], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23],
  ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]
] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv6')
}

export function isBlockedAddress (address: string): boolean {
  const family = net.isIP(address)
  if (family === 0) return true
  return blockedAddresses.check(address, family === 4 ? 'ipv4' : 'ipv6')
}

export function parseImageUrl (rawUrl: unknown): URL {
  if (typeof rawUrl !== 'string') throw new Error('Image URL must be a string')
  const url = new URL(rawUrl)
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error(`Image URL protocol ${url.protocol} is not allowed`)
  if (url.username !== '' || url.password !== '') throw new Error('Image URL must not contain credentials')
  const host = url.hostname.replace(/^\[(.*)\]$/, '$1')
  if (net.isIP(host) !== 0 && isBlockedAddress(host)) throw new Error(`Image URL host ${host} is not allowed`)
  return url
}

// Validates the addresses the socket actually connects to, so DNS rebinding cannot bypass the check
const safeLookup: net.LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { ...options, all: true }, (error, addresses) => {
    if (error) {
      callback(error, '', 0)
      return
    }
    const blocked = addresses.find(({ address }) => isBlockedAddress(address))
    if (blocked !== undefined || addresses.length === 0) {
      callback(new Error(`Image URL host ${hostname} resolves to a disallowed address`), '', 0)
      return
    }
    if (options.all === true) {
      (callback as unknown as (err: null, addresses: dns.LookupAddress[]) => void)(null, addresses)
    } else {
      callback(null, addresses[0].address, addresses[0].family)
    }
  })
}

export async function fetchImage (url: URL): Promise<http.IncomingMessage> {
  const client = url.protocol === 'https:' ? https : http
  return await new Promise((resolve, reject) => {
    const request = client.get(url, { lookup: safeLookup, timeout: FETCH_TIMEOUT_MS }, (response) => {
      const status = response.statusCode ?? 0
      if (status < 200 || status >= 300) {
        response.resume()
        reject(new Error(`url returned status code ${status}`))
        return
      }
      resolve(response)
    })
    request.on('timeout', () => { request.destroy(new Error('Image URL request timed out')) })
    request.on('error', reject)
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
          const response = await fetchImage(parseImageUrl(url))
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(response.pipe(fileStream))
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
