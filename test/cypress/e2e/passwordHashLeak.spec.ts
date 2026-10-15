describe('/rest/user/whoami', () => {
  beforeEach(() => {
    cy.login({ email: 'admin@juice-sh.op', password: 'admin123' })
  })

  it('should not leak the password hash or TOTP secret via fields parameter', () => {
    cy.request('/rest/user/whoami?fields=id,email,password,totpSecret').then((res) => {
      expect(res.body.user.email).to.equal('admin@juice-sh.op')
      expect(res.body.user).to.not.have.property('password')
      expect(res.body.user).to.not.have.property('totpSecret')
    })
  })
})
