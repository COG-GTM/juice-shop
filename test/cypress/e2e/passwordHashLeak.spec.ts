describe('/rest/user/whoami', () => {
  beforeEach(() => {
    cy.login({ email: 'admin@juice-sh.op', password: 'admin123' })
  })

  it('should not leak the password hash via the fields parameter', () => {
    cy.request({
      method: 'GET',
      url: '/rest/user/whoami?fields=id,email,password'
    }).then((res) => {
      expect(res.body.user.password).to.equal(undefined)
      expect(res.body.user.email).to.be.a('string')
    })
  })
})
