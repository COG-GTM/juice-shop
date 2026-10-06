describe('/metrics/', () => {
  describe('challenge "exposedMetrics"', () => {
    it('should deny anonymous access to the /metrics route', () => {
      cy.request({ url: '/metrics', failOnStatusCode: false }).its('status').should('eq', 403)
    })

    it('Challenge is solved on accessing the /metrics route as admin', () => {
      cy.login({ email: 'admin', password: 'admin123' })
      cy.getCookie('token').then((token) => {
        cy.request({ url: '/metrics', headers: { Authorization: `Bearer ${token?.value}` } }).its('status').should('eq', 200)
      })
      cy.expectChallengeSolved({ challenge: 'Exposed Metrics' })
    })
  })
})
