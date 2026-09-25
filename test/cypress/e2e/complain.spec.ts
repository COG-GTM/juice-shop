describe('/#/complain', () => {
  beforeEach(() => {
    cy.login({
      email: 'admin',
      password: 'admin123'
    })

    cy.visit('/#/complain')
  })

  describe('challenge "uploadSize"', () => {
    it('should be possible to upload files greater 100 KB directly through backend', () => {
      cy.window().then(async () => {
        const over100KB = Array.apply(null, new Array(11000)).map(

          String.prototype.valueOf,
          '1234567890'
        )
        const blob = new Blob(over100KB, { type: 'application/pdf' })

        const data = new FormData()
        data.append('file', blob, 'invalidSizeForClient.pdf')

        await fetch(`${Cypress.config('baseUrl')}/file-upload`, {
          method: 'POST',
          cache: 'no-cache',
          body: data
        })
      })
      cy.expectChallengeSolved({ challenge: 'Upload Size' })
    })
  })

  describe('challenge "uploadType"', () => {
    it('should be possible to upload files with other extension than .pdf directly through backend', () => {
      cy.window().then(async () => {
        const data = new FormData()
        const blob = new Blob(['test'], { type: 'application/x-msdownload' })
        data.append('file', blob, 'invalidTypeForClient.exe')

        await fetch(`${Cypress.config('baseUrl')}/file-upload`, {
          method: 'POST',
          cache: 'no-cache',
          body: data
        })
      })
      cy.expectChallengeSolved({ challenge: 'Upload Type' })
    })
  })

  describe('challenge "deprecatedInterface"', () => {
    it('should be possible to upload XML files', () => {
      cy.get('#complaintMessage').type('XML all the way!')
      cy.get('#file').selectFile('test/files/deprecatedTypeForServer.xml')
      cy.get('#submitButton').click()
      cy.expectChallengeSolved({ challenge: 'Deprecated Interface' })
    })
  })

  describe('XXE attacks on the deprecated B2B interface', () => {
    for (const [os, payload, disclosureMarker] of [['Windows', 'xxeForWindows.xml', '; for 16-bit app support'], ['Linux', 'xxeForLinux.xml', 'root:']]) {
      it(`should not disclose local files via .xml upload with ${os}-specific XXE attack`, () => {
        cy.task('isDocker').then((isDocker) => {
          if (!isDocker) {
            cy.intercept('POST', '/file-upload').as('xxeUpload')
            cy.get('#complaintMessage').type(`XXE File Exfiltration ${os}!`)
            cy.get('#file').selectFile(`test/files/${payload}`)
            cy.get('#submitButton').click()
            cy.wait('@xxeUpload').then(({ response }) => {
              expect(response?.statusCode).to.equal(410)
              expect(JSON.stringify(response?.body)).to.not.contain(disclosureMarker)
            })
            cy.expectChallengeUnsolved({ challenge: 'XXE Data Access' })
          }
        })
      })
    }

    for (const [attack, payload] of [['dev/random', 'xxeDevRandom.xml'], ['Quadratic Blowup', 'xxeQuadraticBlowup.xml']]) {
      it(`should not stall the server via .xml upload with ${attack} attack`, () => {
        cy.task('isDocker').then((isDocker) => {
          if (!isDocker) {
            cy.intercept('POST', '/file-upload').as('xxeUpload')
            cy.get('#complaintMessage').type(`XXE ${attack}!`)
            cy.get('#file').selectFile(`test/files/${payload}`)
            cy.get('#submitButton').click()
            cy.wait('@xxeUpload').then(({ response }) => {
              expect(response?.statusCode).to.be.at.least(410)
            })
            cy.wait(5000) // Wait for 2.5x timeout of XML parser
            cy.expectChallengeUnsolved({ challenge: 'XXE DoS' })
          }
        })
      })
    }
  })

  describe('challenge "yamlBomb"', () => {
    it('should be solved via .yaml upload with a Billion Laughs-style attack', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.get('#complaintMessage').type('YAML Bomb!')
          cy.get('#file').selectFile('test/files/yamlBomb.yml')
          cy.get('#submitButton').click()
          cy.wait(5000) // Wait for 2.5x possible timeout of YAML parser
          cy.expectChallengeSolved({ challenge: 'Memory Bomb' })
        }
      })
    })
  })

  describe('challenge "arbitraryFileWrite"', () => {
    it('should be possible to upload zip file with filenames having path traversal', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.get('#complaintMessage').type('Zip Slip!')
          cy.get('#file').selectFile('test/files/arbitraryFileWrite.zip')
          cy.get('#submitButton').click()
          cy.expectChallengeSolved({ challenge: 'Arbitrary File Write' })
        }
      })
    })
  })

  describe('challenge "videoXssChallenge"', () => {
    it('should be possible to inject js in subtitles by uploading zip file with filenames having path traversal', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.get('#complaintMessage').type('Here we go!')
          cy.get('#file').selectFile('test/files/videoExploit.zip')
          cy.get('#submitButton').click()
          cy.visit('/promotion')

          cy.on('window:alert', (t) => {
            expect(t).to.equal('xss')
          })
          cy.visit('/')
          cy.expectChallengeSolved({ challenge: 'Video XSS' })
        }
      })
    })
  })
})
