/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import fs from 'node:fs'
import path from 'node:path'
import { parseInSandbox, sandboxedParserLimits } from '../../lib/sandboxedParser'

const expect = chai.expect

describe('sandboxedParser', function () {
  this.timeout(30000)

  async function parseWhileMeasuringEventLoop (...args: Parameters<typeof parseInSandbox>) {
    let last = Date.now()
    let maxGap = 0
    const ticker = setInterval(() => {
      maxGap = Math.max(maxGap, Date.now() - last)
      last = Date.now()
    }, 20)
    const result = await parseInSandbox(...args)
    clearInterval(ticker)
    return { result, maxGap }
  }

  it('should return parsed YAML as JSON', async () => {
    const result = await parseInSandbox('yaml', 'juice: shop')
    expect(result).to.deep.equal({ status: 'ok', output: '{"juice":"shop"}', message: undefined, disclosesFile: false })
  })

  it('should report YAML syntax errors', async () => {
    const result = await parseInSandbox('yaml', 'juice: "shop')
    expect(result.status).to.equal('error')
    expect(result.message).to.be.a('string')
  })

  it('should abort a YAML alias bomb without blocking the event loop', async () => {
    const bomb = fs.readFileSync(path.resolve(__dirname, '../files/yamlBomb.yml'), 'utf8')
    const { result, maxGap } = await parseWhileMeasuringEventLoop('yaml', bomb)
    expect(['timeout', 'exhausted']).to.include(result.status)
    expect(maxGap).to.be.below(500)
  })

  it('should refuse to start more parsers than the concurrency limit', async () => {
    const results = await Promise.all(Array.from({ length: sandboxedParserLimits.maxConcurrentParsers + 1 }, async () => await parseInSandbox('yaml', 'a: 1')))
    expect(results.filter(({ status }) => status === 'busy')).to.have.length(1)
    expect(results.filter(({ status }) => status === 'ok')).to.have.length(sandboxedParserLimits.maxConcurrentParsers)
  })

  it('should cap the returned output length', async () => {
    const result = await parseInSandbox('yaml', `a: "${'x'.repeat(sandboxedParserLimits.maxOutputLength * 2)}"`)
    expect(result.status).to.equal('ok')
    expect(result.output).to.have.length(sandboxedParserLimits.maxOutputLength)
  })

  it('should not substitute external XML entities unless asked to', async () => {
    const xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>'
    const result = await parseInSandbox('xml', xml)
    expect(result.status).to.equal('ok')
    expect(result.output).to.contain('&xxe;')
  })

  it('should detect disclosed file contents beyond the output length cap', async () => {
    const xml = `<foo><padding>${'a'.repeat(sandboxedParserLimits.maxOutputLength)}</padding><file>root:x:0:0:root:/root:/bin/bash</file></foo>`
    const result = await parseInSandbox('xml', xml)
    expect(result.status).to.equal('ok')
    expect(result.output).to.have.length(sandboxedParserLimits.maxOutputLength)
    expect(result.disclosesFile).to.equal(true)
  })

  it('should not block the event loop on an XML entity pointing at /dev/random', async () => {
    const xml = fs.readFileSync(path.resolve(__dirname, '../files/xxeDevRandom.xml'), 'utf8')
    const { result, maxGap } = await parseWhileMeasuringEventLoop('xml', xml, { substituteEntities: true })
    expect(result.status).to.not.equal('ok')
    expect(maxGap).to.be.below(500)
  })
})
