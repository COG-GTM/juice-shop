describe('/#/login', () => {
  beforeEach(() => {
    cy.visit('/#/login')
  })

  describe('challenge "loginAdmin"', () => {
    it('should not log in with SQLI attack on email field using "\' or 1=1--"', () => {
      cy.get('#email').type("' or 1=1--")
      cy.get('#password').type('a')
      cy.get('#loginButton').click()
      cy.get('.error').should('be.visible')
      cy.url().should('include', '/login')
    })

    it('should log in Admin with the original admin credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`admin@${appDomain}`)
          cy.get('#password').type('admin123')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Login Admin' })
    })
  })

  describe('challenge "loginJim"', () => {
    it('should log in Jim with his original credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`jim@${appDomain}`)
          cy.get('#password').type('ncc-1701')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Login Jim' })
    })
  })

  describe('challenge "loginBender"', () => {
    it('should log in Bender with his original credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`bender@${appDomain}`)
          cy.get('#password').type('OhG0dPlease1nsertLiquor!')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Login Bender' })
    })
  })

  describe('challenge "adminCredentials"', () => {
    it('should be able to log in with original (weak) admin credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`admin@${appDomain}`)
          cy.get('#password').type('admin123')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Password Strength' })
    })
  })

  describe('challenge "loginSupport"', () => {
    it('should be able to log in with original support-team credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`support@${appDomain}`)
          cy.get('#password').type('J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Login Support Team' })
    })
  })

  describe('challenge "loginRapper"', () => {
    it('should be able to log in with original MC SafeSearch credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`mc.safesearch@${appDomain}`)
          cy.get('#password').type('Mr. N00dles')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Login MC SafeSearch' })
    })
  })

  describe('challenge "loginAmy"', () => {
    it('should be able to log in with original Amy credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`amy@${appDomain}`)
          cy.get('#password').type('K1f.....................')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Login Amy' })
    })
  })

  describe('challenge "dlpPasswordSpraying"', () => {
    it('should be able to log in with original Jannik credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`J12934@${appDomain}`)
          cy.get('#password').type('0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Leaked Access Logs' })
    })
  })

  describe('challenge "twoFactorAuthUnsafeSecretStorage"', () => {
    it('should be able to log into a existing 2fa protected account given the right token', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`wurstbrot@${appDomain}`)
          cy.get('#password').type('EinBelegtesBrotMitSchinkenSCHINKEN!')
          cy.get('#loginButton').click()
        }
      )

      cy.task<string>('GenerateAuthenticator', 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH').then(
        (totpToken: string) => {
          void cy.get('#totpToken').type(totpToken)
          void cy.get('#totpSubmitButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Two Factor Authentication' })
    })
  })

  describe('challenge "oauthUserPassword"', () => {
    it('should be able to log in as bjoern.kimminich@gmail.com with base64-encoded email as password', () => {
      cy.get('#email').type('bjoern.kimminich@gmail.com')
      cy.get('#password').type('bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=')
      cy.get('#loginButton').click()

      cy.expectChallengeSolved({ challenge: 'Login Bjoern' })
    })
  })

  describe('challenge "exposedCredentialsChallenge"', () => {
    it('should be able to log in with testing credentials that are leaked on client', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`testing@${appDomain}`)
          cy.get('#password').type('IamUsedForTesting')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Exposed credentials' })
    })
  })
})
