/// <reference types="cypress" />

describe('Sign and Verify Flow', () => {
  let testKeyId: string
  const testData = 'Hello, this is a complete end-to-end test!'

  beforeEach(() => {
    cy.setupAuth()

    // Intercept keys API for waiting
    cy.intercept('GET', '**/api/hsm/keys*').as('getKeys')

    // Create a test key
    cy.createKeyViaApi({ algorithm: 'ED25519', purpose: 'SIGN' }).then((key) => {
      testKeyId = key.key_id
    })
  })

  afterEach(() => {
    if (testKeyId) {
      cy.deleteKeyViaApi(testKeyId)
    }
  })

  describe('Complete Sign → Verify Flow', () => {
    it('signs data and then verifies the signature', () => {
      // Step 1: Navigate to sign page
      cy.visit('/operations/sign')
      cy.wait('@getKeys')

      // Step 2: Select the key
      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').contains(testKeyId.substring(0, 8)).click()

      // Step 3: Enter data to sign
      cy.get('textarea#data').clear().type(testData)

      // Step 4: Click sign
      cy.contains('button', /sign data/i).click()

      // Step 5: Wait for signature result
      cy.contains(/signature result/i, { timeout: 10000 }).should('be.visible')

      // Step 6: Get the signature value and verify it
      cy.get('.font-mono')
        .invoke('text')
        .then((signature) => {
          const cleanSignature = signature.trim()
          expect(cleanSignature.length).to.be.greaterThan(10)

          // Step 7: Navigate to verify page
          cy.visit('/operations/verify')
          cy.wait('@getKeys')

          // Step 8: Select the same key
          cy.get('button[role="combobox"]').first().click()
          cy.get('[role="option"]').contains(testKeyId.substring(0, 8)).click()

          // Step 9: Enter the original data
          cy.get('textarea#data').clear().type(testData)

          // Step 10: Enter the signature
          cy.get('textarea#signature').clear().type(cleanSignature)

          // Step 11: Click verify
          cy.contains('button', /verify signature/i).click()

          // Step 12: Should show verification result
          cy.contains(/verification result/i, { timeout: 10000 }).should('be.visible')
        })
    })

    it('detects tampered data', () => {
      // Sign original data
      cy.visit('/operations/sign')
      cy.wait('@getKeys')

      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').contains(testKeyId.substring(0, 8)).click()

      cy.get('textarea#data').clear().type(testData)
      cy.contains('button', /sign data/i).click()

      cy.contains(/signature result/i, { timeout: 10000 }).should('be.visible')

      cy.get('.font-mono')
        .invoke('text')
        .then((signature) => {
          const cleanSignature = signature.trim()

          // Navigate to verify page
          cy.visit('/operations/verify')
          cy.wait('@getKeys')

          cy.get('button[role="combobox"]').first().click()
          cy.get('[role="option"]').contains(testKeyId.substring(0, 8)).click()

          // Enter tampered data
          cy.get('textarea#data').clear().type('This data has been tampered with!')
          cy.get('textarea#signature').clear().type(cleanSignature)

          cy.contains('button', /verify signature/i).click()

          // Should show verification result (will indicate invalid)
          cy.contains(/verification result/i, { timeout: 10000 }).should('be.visible')
        })
    })
  })

  describe('Navigation Between Operations', () => {
    it('navigates from sign to verify page', () => {
      cy.visit('/operations/sign')
      cy.wait('@getKeys')
      cy.url().should('include', '/operations/sign')

      cy.contains('Back to Operations').click()
      cy.url().should('include', '/operations')
      cy.url().should('not.include', '/sign')
    })

    it('navigates from verify to operations page', () => {
      cy.visit('/operations/verify')
      cy.wait('@getKeys')
      cy.url().should('include', '/operations/verify')

      cy.contains('Back to Operations').click()
      cy.url().should('include', '/operations')
      cy.url().should('not.include', '/verify')
    })

    it('preserves authentication across operations', () => {
      cy.visit('/operations/sign')
      cy.wait('@getKeys')
      cy.url().should('not.include', '/login')

      cy.visit('/operations/verify')
      cy.wait('@getKeys')
      cy.url().should('not.include', '/login')
    })
  })
})
