describe('/', () => {
  describe('challenge "jwtUnsigned"', () => {
    it('should reject an unsigned token with email jwtn3d@juice-sh.op in the payload ', () => {
      cy.request({
        url: '/rest/user/authentication-details',
        headers: { Authorization: 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.' },
        failOnStatusCode: false
      }).its('status').should('eq', 401)
      cy.request('/api/Challenges/?name=Unsigned JWT').its('body.data.0.solved').should('eq', false)
    })
  })

  describe('challenge "jwtForged"', () => {
    it('should reject a token HMAC-signed with public RSA key with email rsa_lord@juice-sh.op in the payload ', () => {
      cy.request({
        url: '/rest/user/authentication-details',
        headers: { Authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgzMDM3NzExfQ.gShXDT5TrE5736mpIbfVDEcQbLfteJaQUG7Z0PH8Xc8' },
        failOnStatusCode: false
      }).its('status').should('eq', 401)
      cy.request('/api/Challenges/?name=Forged Signed JWT').its('body.data.0.solved').should('eq', false)
    })
  })
})
