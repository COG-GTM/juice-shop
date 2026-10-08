describe('/metrics/', () => {
  describe('challenge "exposedMetrics"', () => {
    it('should deny anonymous access to the /metrics route', () => {
      cy.request({ url: '/metrics', failOnStatusCode: false }).its('status').should('eq', 401)
    })

    it('Challenge is solved on accessing the /metrics route as admin', () => {
      cy.login({ email: 'admin', password: 'admin123' })
      cy.request('/metrics')
      cy.expectChallengeSolved({ challenge: 'Exposed Metrics' })
    })
  })
})
