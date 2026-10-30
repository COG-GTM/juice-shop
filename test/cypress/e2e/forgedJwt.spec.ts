const unsignedToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.'
const hmacSignedToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgzMDM3NzExfQ.gShXDT5TrE5736mpIbfVDEcQbLfteJaQUG7Z0PH8Xc8'

function expectChallengeNotSolved (challenge: string) {
  cy.request({ method: 'GET', url: '/api/Challenges/?name=' + challenge }).then((response) => {
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    expect(response.body.data[0].solved).to.be.false
  })
}

function expectRejected (token: string) {
  cy.request({
    method: 'GET',
    url: '/rest/basket/1',
    headers: { Authorization: `Bearer ${token}` },
    failOnStatusCode: false
  }).its('status').should('eq', 401)
}

describe('/', () => {
  describe('challenge "jwtUnsigned"', () => {
    it('should reject an unsigned token with email jwtn3d@juice-sh.op in the payload', () => {
      cy.window().then(() => {
        localStorage.setItem('token', unsignedToken)
      })
      cy.visit('/')
      expectRejected(unsignedToken)
      expectChallengeNotSolved('Unsigned JWT')
    })
  })

  describe('challenge "jwtForged"', () => {
    it('should reject a token HMAC-signed with public RSA key with email rsa_lord@juice-sh.op in the payload', () => {
      cy.window().then(() => {
        localStorage.setItem('token', hmacSignedToken)
      })
      cy.visit('/#/')
      expectRejected(hmacSignedToken)
      expectChallengeNotSolved('Forged Signed JWT')
    })
  })
})
