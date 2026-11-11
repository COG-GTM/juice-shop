describe('/metrics/', () => {
  describe('challenge "exposedMetrics"', () => {
    it('Challenge is solved on accessing the /metrics route', () => {
      cy.request({ url: '/metrics', failOnStatusCode: false }).its('status').should('eq', 401)
      cy.expectChallengeSolved({ challenge: 'Exposed Metrics' })
    })
  })
})
