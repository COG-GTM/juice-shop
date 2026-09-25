/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import net from 'node:net'
import config from 'config'
import { IpFilter } from 'express-ipfilter'

export const isValidIpOrCidr = (entry: string) => {
  if (typeof entry !== 'string') return false
  const [address, prefix, ...surplus] = entry.split('/')
  if (surplus.length > 0) return false
  const version = net.isIP(address)
  if (version === 0) return false
  if (prefix === undefined) return true
  if (!/^\d{1,3}$/.test(prefix)) return false
  return Number(prefix) <= (version === 4 ? 32 : 128)
}

export const accountingIpAllowlist = (): string[] => {
  const configured = config.has('application.accountingIpAllowlist') ? config.get<string[] | null>('application.accountingIpAllowlist') : null
  return Array.isArray(configured) ? configured : []
}

export const accountingIpFilter = (allowlist = accountingIpAllowlist()): Array<ReturnType<typeof IpFilter>> => {
  const invalidEntries = allowlist.filter((entry) => !isValidIpOrCidr(entry))
  if (invalidEntries.length > 0) {
    throw new Error(`Invalid IP address or CIDR range in application.accountingIpAllowlist: ${invalidEntries.join(', ')}`)
  }
  return allowlist.length > 0 ? [IpFilter(allowlist, { mode: 'allow' })] : []
}
