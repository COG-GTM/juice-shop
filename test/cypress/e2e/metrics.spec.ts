describe('/metrics/', () => {
  describe('challenge "exposedMetrics"', () => {
    it('Metrics are not exposed to anonymous users', () => {
      cy.request({ url: '/metrics', failOnStatusCode: false }).its('status').should('eq', 403)
    })

    it('Challenge is solved on accessing the /metrics route as admin', () => {
      cy.login({ email: 'admin', password: 'admin123' })
      cy.window().then(() => {
        cy.request({
          url: '/metrics',
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        })
      })
      cy.expectChallengeSolved({ challenge: 'Exposed Metrics' })
    })
  })
})
