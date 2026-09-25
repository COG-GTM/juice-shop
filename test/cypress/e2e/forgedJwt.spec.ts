describe('/', () => {
  describe('challenge "jwtUnsigned"', () => {
    it('should accept an unsigned token with email jwtn3d@juice-sh.op in the payload ', () => {
      cy.window().then(() => {
        localStorage.setItem(
          'token',
          'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.'
        )
      })
      cy.visit('/')
      cy.expectChallengeSolved({ challenge: 'Unsigned JWT' })
    })
  })

  describe('challenge "jwtForged"', () => {
    const base64url = (value: string) => btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')

    it('should accept a token HMAC-signed with public RSA key with email rsa_lord@juice-sh.op in the payload ', () => {
      cy.task('isWindows').then((isWindows) => {
        if (!isWindows) {
          cy.request('/encryptionkeys/jwt.pub').then((response) => {
            const signingInput = `${base64url(JSON.stringify({ typ: 'JWT', alg: 'HS256' }))}.${base64url(JSON.stringify({ data: { email: 'rsa_lord@juice-sh.op' }, iat: 1583037711 }))}`
            cy.window().then(async (win) => {
              const encoder = new TextEncoder()
              const key = await win.crypto.subtle.importKey('raw', encoder.encode(response.body as string), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
              const signature = await win.crypto.subtle.sign('HMAC', key, encoder.encode(signingInput))
              const encodedSignature = base64url(String.fromCharCode(...new Uint8Array(signature)))
              localStorage.setItem('token', `${signingInput}.${encodedSignature}`)
            })
            cy.visit('/#/')

            cy.expectChallengeSolved({ challenge: 'Forged Signed JWT' })
          })
        }
      })
    })
  })
})
