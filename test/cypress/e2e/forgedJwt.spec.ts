describe('/', () => {
  const unsignedToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.'
  const hmacForgedToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgzMDM3NzExfQ.gShXDT5TrE5736mpIbfVDEcQbLfteJaQUG7Z0PH8Xc8'

  for (const [name, token] of [['unsigned', unsignedToken], ['HMAC-signed with public RSA key', hmacForgedToken]]) {
    describe(`${name} token`, () => {
      it('should be rejected by isAuthorized routes', () => {
        cy.request({ url: '/api/Users', headers: { Authorization: `Bearer ${token}` }, failOnStatusCode: false })
          .its('status').should('eq', 401)
      })

      it('should not create an authenticated session', () => {
        cy.request({ url: '/rest/user/whoami', headers: { Authorization: `Bearer ${token}`, Cookie: `token=${token}` } })
          .its('body.user').should('deep.equal', {})
      })
    })
  }
})
