/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const blockedAddresses = new net.BlockList()
blockedAddresses.addSubnet('0.0.0.0', 8, 'ipv4')
blockedAddresses.addSubnet('10.0.0.0', 8, 'ipv4')
blockedAddresses.addSubnet('100.64.0.0', 10, 'ipv4')
blockedAddresses.addSubnet('127.0.0.0', 8, 'ipv4')
blockedAddresses.addSubnet('169.254.0.0', 16, 'ipv4')
blockedAddresses.addSubnet('172.16.0.0', 12, 'ipv4')
blockedAddresses.addSubnet('192.168.0.0', 16, 'ipv4')
blockedAddresses.addSubnet('224.0.0.0', 3, 'ipv4')
blockedAddresses.addSubnet('::', 128, 'ipv6')
blockedAddresses.addSubnet('::1', 128, 'ipv6')
blockedAddresses.addSubnet('::ffff:0:0', 96, 'ipv6')
blockedAddresses.addSubnet('64:ff9b::', 96, 'ipv6')
blockedAddresses.addSubnet('fc00::', 7, 'ipv6')
blockedAddresses.addSubnet('fe80::', 10, 'ipv6')
blockedAddresses.addSubnet('ff00::', 8, 'ipv6')

const isBlockedAddress = (address: string) => {
  const family = net.isIP(address)
  return family === 0 || blockedAddresses.check(address, family === 6 ? 'ipv6' : 'ipv4')
}

export const isSafeImageUrl = async (input: string): Promise<boolean> => {
  let parsed: URL
  try {
    parsed = new URL(input)
  } catch {
    return false
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false
  if (parsed.username !== '' || parsed.password !== '') return false
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '')
  if (hostname === '' || hostname === 'localhost' || hostname.endsWith('.localhost')) return false
  if (net.isIP(hostname) !== 0) return !isBlockedAddress(hostname)
  try {
    const addresses = await dns.lookup(hostname, { all: true })
    return addresses.length > 0 && addresses.every(({ address }) => !isBlockedAddress(address))
  } catch {
    return false
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
          if (typeof url !== 'string' || !(await isSafeImageUrl(url))) {
            throw new Error('url is not an allowed public http(s) image location')
          }
          const response = await fetch(url, { redirect: 'error' })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          if (!(response.headers.get('content-type') ?? '').startsWith('image/')) {
            throw new Error('url did not return an image')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; keeping existing profile image`)
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
