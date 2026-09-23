describe('/metrics/', () => {
  it('Metrics are not served to anonymous users', () => {
    cy.request({ url: '/metrics', failOnStatusCode: false }).then((response) => {
      expect(response.status).to.equal(403)
    })
  })

  it('Metrics are served to administrators', () => {
    cy.login({ email: 'admin', password: 'admin123' })
    cy.window().then((window) => {
      const token = window.localStorage.getItem('token')
      cy.request({ url: '/metrics', headers: { Authorization: `Bearer ${token}` } }).then((response) => {
        expect(response.status).to.equal(200)
        expect(response.body).to.contain('_users_registered_total')
      })
    })
  })
})
