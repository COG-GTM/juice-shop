describe('/', () => {
  const expectChallengeNotSolved = (challengeName: string) => {
    cy.wait(2000)
    cy.request({ method: 'GET', url: '/api/Challenges/?name=' + challengeName, timeout: 60000 }).then((response) => {
      expect(response.body.data[0].solved).to.equal(false)
    })
  }

  describe('challenge "jwtUnsigned"', () => {
    it('should reject an unsigned token with email jwtn3d@juice-sh.op in the payload ', () => {
      cy.window().then(() => {
        localStorage.setItem(
          'token',
          'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.'
        )
      })
      cy.visit('/')
      expectChallengeNotSolved('Unsigned JWT')
    })
  })

  describe('challenge "jwtForged"', () => {
    it('should reject a token HMAC-signed with public RSA key with email rsa_lord@juice-sh.op in the payload ', () => {
      cy.window().then(() => {
        localStorage.setItem(
          'token',
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgzMDM3NzExfQ.gShXDT5TrE5736mpIbfVDEcQbLfteJaQUG7Z0PH8Xc8'
        )
      })
      cy.visit('/#/')
      expectChallengeNotSolved('Forged Signed JWT')
    })
  })
})
