describe('/', () => {
  const encode = (part: object) => btoa(JSON.stringify(part)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
  const payload = (email: string) => encode({ data: { email }, iat: 1508639612, exp: 9999999999 })

  describe('challenge "jwtUnsigned"', () => {
    it('should reject an unsigned token with email jwtn3d@juice-sh.op in the payload', () => {
      const token = `${encode({ alg: 'none', typ: 'JWT' })}.${payload('jwtn3d@juice-sh.op')}.`
      cy.request({ url: '/rest/basket/1', headers: { Authorization: `Bearer ${token}` }, failOnStatusCode: false })
        .its('status').should('eq', 401)
      cy.request('/api/Challenges/?key=jwtUnsignedChallenge').its('body.data.0.solved').should('eq', false)
    })
  })

  describe('challenge "jwtForged"', () => {
    it('should reject an HMAC-signed token with email rsa_lord@juice-sh.op in the payload', () => {
      const token = `${encode({ alg: 'HS256', typ: 'JWT' })}.${payload('rsa_lord@juice-sh.op')}.${encode({ sig: 'not-the-signing-key' })}`
      cy.request({ url: '/rest/basket/1', headers: { Authorization: `Bearer ${token}` }, failOnStatusCode: false })
        .its('status').should('eq', 401)
      cy.request('/api/Challenges/?key=jwtForgedChallenge').its('body.data.0.solved').should('eq', false)
    })
  })
})
