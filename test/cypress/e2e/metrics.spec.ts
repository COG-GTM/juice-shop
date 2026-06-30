describe('/metrics/', () => {
  describe('challenge "exposedMetrics"', () => {
    it('rejects anonymous access and solves the challenge for admin', () => {
      cy.request({ url: '/metrics', failOnStatusCode: false }).then((response) => {
        expect(response.status).to.eq(403)
      })

      cy.request({
        method: 'POST',
        url: '/rest/user/login',
        body: {
          email: 'admin@juice-sh.op',
          password: 'admin123'
        }
      }).then((response) => {
        cy.request({
          url: '/metrics',
          headers: {
            Authorization: `Bearer ${response.body.authentication.token}`
          }
        }).then((metricsResponse) => {
          expect(metricsResponse.status).to.eq(200)
          cy.expectChallengeSolved({ challenge: 'Exposed Metrics' })
        })
      })
    })
  })
})
