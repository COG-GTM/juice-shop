describe('/metrics/', () => {
  it('Metrics are not served to anonymous users', () => {
    cy.request({ url: '/metrics', failOnStatusCode: false }).its('status').should('equal', 403)
  })

  describe('challenge "exposedMetrics"', () => {
    it('Challenge is solved on accessing the /metrics route as admin', () => {
      cy.login({ email: 'admin', password: 'admin123' })
      cy.window().then((window) => {
        cy.request({ url: '/metrics', headers: { Authorization: `Bearer ${window.localStorage.getItem('token')}` } })
      })
      cy.expectChallengeSolved({ challenge: 'Exposed Metrics' })
    })
  })
})
