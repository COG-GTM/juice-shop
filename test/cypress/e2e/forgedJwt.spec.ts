describe('/rest/basket', () => {
  describe('with an unsigned JWT', () => {
    it('should be rejected as unauthorized', () => {
      cy.request({
        url: '/rest/basket/1',
        headers: {
          Authorization:
            'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.'
        },
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.equal(401)
      })
    })
  })

  describe('with a JWT HMAC-signed using the public RSA key', () => {
    it('should be rejected as unauthorized', () => {
      cy.request({
        url: '/rest/basket/1',
        headers: {
          Authorization:
            'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgzMDM3NzExfQ.gShXDT5TrE5736mpIbfVDEcQbLfteJaQUG7Z0PH8Xc8'
        },
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.equal(401)
      })
    })
  })
})
