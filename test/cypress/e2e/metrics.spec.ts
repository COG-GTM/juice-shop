describe('/metrics/', () => {
  describe('challenge "exposedMetrics"', () => {
    it('Challenge is solved on accessing the /metrics route as an administrator', () => {
      cy.login({ email: 'admin', password: 'admin123' })
      cy.window().then((win) => {
        cy.request({ url: '/metrics', headers: { Authorization: `Bearer ${win.localStorage.getItem('token')}` } })
      })
      cy.expectChallengeSolved({ challenge: 'Exposed Metrics' })
    })
  })
})
