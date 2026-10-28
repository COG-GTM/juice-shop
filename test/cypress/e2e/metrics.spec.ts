describe('/metrics/', () => {
  it('rejects requests without the scrape token', () => {
    cy.request({ url: '/metrics', failOnStatusCode: false }).its('status').should('eq', 401)
  })

  describe('challenge "exposedMetrics"', () => {
    it('Challenge is solved on accessing the /metrics route even without the scrape token', () => {
      cy.request({ url: '/metrics', failOnStatusCode: false })
      cy.expectChallengeSolved({ challenge: 'Exposed Metrics' })
    })

    it('serves the metrics with the scrape token', () => {
      cy.request({
        url: '/metrics',
        headers: { Authorization: `Bearer ${Cypress.env('METRICS_SCRAPE_TOKEN')}` }
      }).its('body').should('match', /_version_info/)
    })
  })
})
