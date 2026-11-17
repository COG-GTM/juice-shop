describe('/', () => {
  const base64url = (input: string | ArrayBuffer) => {
    const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input)
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }

  const unsignedToken = `${base64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${base64url(JSON.stringify({ data: { email: 'jwtn3d@juice-sh.op' }, iat: 1508639612, exp: 9999999999 }))}.`

  const hmacSignWithServerPublicKey = (payload: object) =>
    cy.request('/encryptionkeys/jwt.pub').its('body').then((publicKey: string) =>
      cy.window().then(async (win) => {
        const unsigned = `${base64url(JSON.stringify({ typ: 'JWT', alg: 'HS256' }))}.${base64url(JSON.stringify(payload))}`
        const key = await win.crypto.subtle.importKey('raw', new TextEncoder().encode(publicKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
        const signature = await win.crypto.subtle.sign('HMAC', key, new TextEncoder().encode(unsigned))
        return `${unsigned}.${base64url(signature)}`
      })
    )

  const expectTokenRejected = (token: string, challenge: string) => {
    cy.window().then(() => {
      localStorage.setItem('token', token)
    })
    cy.visit('/')
    cy.request({
      method: 'GET',
      url: '/rest/basket/1',
      headers: { Authorization: `Bearer ${token}` },
      failOnStatusCode: false
    }).its('status').should('eq', 401)
    cy.request(`/api/Challenges/?name=${challenge}`).its('body.data.0.solved').should('eq', false)
  }

  describe('challenge "jwtUnsigned"', () => {
    it('should reject an unsigned token with email jwtn3d@juice-sh.op in the payload', () => {
      expectTokenRejected(unsignedToken, 'Unsigned JWT')
    })
  })

  describe('challenge "jwtForged"', () => {
    it('should reject a token HMAC-signed with the server\'s current public RSA key with email rsa_lord@juice-sh.op in the payload', () => {
      cy.visit('/')
      hmacSignWithServerPublicKey({ data: { email: 'rsa_lord@juice-sh.op' }, iat: 1583037711 }).then((token: string) => {
        expectTokenRejected(token, 'Forged Signed JWT')
      })
    })
  })
})
