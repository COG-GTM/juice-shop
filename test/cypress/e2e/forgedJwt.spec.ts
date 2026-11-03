const unsignedToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.'
const hmacSignedToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgzMDM3NzExfQ.gShXDT5TrE5736mpIbfVDEcQbLfteJaQUG7Z0PH8Xc8'

function expectRejected (token: string, challenge: string) {
  cy.window().then(() => {
    localStorage.setItem('token', token)
  })
  cy.visit('/#/')
  cy.request({
    method: 'GET',
    url: '/rest/basket/1',
    headers: { Authorization: `Bearer ${token}` },
    failOnStatusCode: false
  }).its('status').should('eq', 401)
  cy.request('/api/Challenges/?name=' + challenge).its('body.data.0.solved').should('eq', false)
}

describe('/', () => {
  describe('challenge "jwtUnsigned"', () => {
    it('should reject an unsigned token with email jwtn3d@juice-sh.op in the payload', () => {
      expectRejected(unsignedToken, 'Unsigned JWT')
    })
  })

  describe('challenge "jwtForged"', () => {
    it('should reject a token HMAC-signed with public RSA key with email rsa_lord@juice-sh.op in the payload', () => {
      expectRejected(hmacSignedToken, 'Forged Signed JWT')
    })
  })
})
