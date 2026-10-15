describe('/metrics/', () => {
  describe('challenge "exposedMetrics"', () => {
    it('should deny anonymous access to the /metrics route', () => {
      cy.request({ url: '/metrics', failOnStatusCode: false }).its('status').should('eq', 401)
    })

    it('Challenge is solved on accessing the /metrics route with the metrics token', () => {
      cy.request({ url: '/metrics', headers: { Authorization: `Bearer ${Cypress.env('METRICS_TOKEN')}` } })
      cy.expectChallengeSolved({ challenge: 'Exposed Metrics' })
    })
  })
})
