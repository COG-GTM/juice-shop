describe('/metrics/', () => {
  const scrapeToken: string | undefined = Cypress.env('METRICS_SCRAPE_TOKEN')

  it('rejects requests without the scrape token', () => {
    cy.request({ url: '/metrics', failOnStatusCode: false }).its('status').should('eq', scrapeToken ? 401 : 404)
  })

  describe('challenge "exposedMetrics"', () => {
    it('Challenge is solved on accessing the /metrics route even without the scrape token', () => {
      cy.request({ url: '/metrics', failOnStatusCode: false })
      cy.expectChallengeSolved({ challenge: 'Exposed Metrics' })
    })

    it('serves the metrics with the scrape token', function () {
      if (!scrapeToken) this.skip()
      cy.request({
        url: '/metrics',
        headers: { Authorization: `Bearer ${scrapeToken}` }
      }).its('body').should('match', /_version_info/)
    })
  })
})
