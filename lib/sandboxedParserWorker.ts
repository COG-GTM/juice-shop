/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import yaml from 'js-yaml'
import libxml from 'libxmljs2'
import { matchesEtcPasswdFile, matchesSystemIniFile } from './fileDisclosure'
import { type SandboxedParseRequest, type SandboxedParseResult } from './sandboxedParser'

function parse ({ kind, data, substituteEntities, maxOutputLength }: SandboxedParseRequest): SandboxedParseResult {
  try {
    const output: string = kind === 'xml'
      ? libxml.parseXml(data, { noblanks: true, noent: substituteEntities, nonet: true, nocdata: true }).toString(false)
      : JSON.stringify(yaml.load(data))
    const disclosesFile = kind === 'xml' && (matchesEtcPasswdFile(output) || matchesSystemIniFile(output))
    return { status: 'ok', output: String(output).substring(0, maxOutputLength), disclosesFile }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err)
    if (err instanceof RangeError && message.includes('Invalid string length')) {
      return { status: 'exhausted', message }
    }
    return { status: 'error', message }
  }
}

process.on('message', (request: SandboxedParseRequest) => {
  process.send?.(parse(request), undefined, undefined, () => process.exit(0))
})

process.send?.({ ready: true })
