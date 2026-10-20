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

const MAX_REDIRECTS = 3
const REQUEST_TIMEOUT_MS = 10000

const blockedAddresses = new net.BlockList()
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv4')
}
for (const [network, prefix] of [
  ['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64], ['2001:db8::', 32],
  ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]
] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv6')
}
const ipv4MappedAddresses = new net.BlockList()
ipv4MappedAddresses.addSubnet('::ffff:0:0', 96, 'ipv6')

export function isBlockedAddress (address: string): boolean {
  const mappedIPv4 = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address)
  if (mappedIPv4) return isBlockedAddress(mappedIPv4[1])
  if (net.isIPv4(address)) return blockedAddresses.check(address, 'ipv4')
  if (net.isIPv6(address)) return ipv4MappedAddresses.check(address, 'ipv6') || blockedAddresses.check(address, 'ipv6')
  return true
}

const safeLookup: net.LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) {
      callback(err, '', 0)
      return
    }
    const blocked = addresses.find(({ address }) => isBlockedAddress(address))
    if (blocked || addresses.length === 0) {
      callback(new Error(`Refusing to connect to non-public address ${blocked?.address ?? hostname}`), '', 0)
      return
    }
    if (options.all) {
      (callback as unknown as (err: null, addresses: dns.LookupAddress[]) => void)(null, addresses)
    } else {
      callback(null, addresses[0].address, addresses[0].family)
    }
  })
}

export function fetchImage (url: string, redirectsLeft = MAX_REDIRECTS): Promise<http.IncomingMessage> {
  return new Promise((resolve, reject) => {
    let target: URL
    try {
      target = new URL(url)
    } catch {
      reject(new Error('url is not a valid absolute URL'))
      return
    }
    if (target.protocol !== 'http:' && target.protocol !== 'https:') {
      reject(new Error(`url protocol ${target.protocol} is not allowed`))
      return
    }
    const hostname = target.hostname.replace(/^\[(.*)\]$/, '$1')
    if (net.isIP(hostname) !== 0 && isBlockedAddress(hostname)) {
      reject(new Error(`Refusing to connect to non-public address ${hostname}`))
      return
    }

    const client = target.protocol === 'https:' ? https : http
    const request = client.get(target, { lookup: safeLookup, timeout: REQUEST_TIMEOUT_MS }, (response) => {
      const status = response.statusCode ?? 0
      if (status >= 300 && status < 400 && response.headers.location) {
        response.resume()
        if (redirectsLeft <= 0) {
          reject(new Error('url exceeded the maximum number of redirects'))
          return
        }
        let location: string
        try {
          location = new URL(response.headers.location, target).href
        } catch {
          reject(new Error('url redirected to an invalid location'))
          return
        }
        fetchImage(location, redirectsLeft - 1).then(resolve, reject)
        return
      }
      if (status < 200 || status >= 300) {
        response.resume()
        reject(new Error('url returned a non-OK status code'))
        return
      }
      if (!/^image\//i.test(response.headers['content-type'] ?? '')) {
        response.resume()
        reject(new Error('url did not return an image content type'))
        return
      }
      resolve(response)
    })
    request.on('timeout', () => { request.destroy(new Error('url request timed out')) })
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
          const response = await fetchImage(url)
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
