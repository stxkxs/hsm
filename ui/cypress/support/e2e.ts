/// <reference types="cypress" />

// Import commands
import './commands'

// ============================================================================
// Global Hooks
// ============================================================================

beforeEach(() => {
  // Intercept common API calls for debugging
  cy.intercept('GET', '**/api/hsm/**').as('apiGet')
  cy.intercept('POST', '**/api/hsm/**').as('apiPost')
  cy.intercept('DELETE', '**/api/hsm/**').as('apiDelete')
})

// ============================================================================
// Error Handling
// ============================================================================

// Prevent Cypress from failing on uncaught exceptions from the app
Cypress.on('uncaught:exception', (err, runnable) => {
  // Log the error for debugging
  console.error('Uncaught exception:', err.message)

  // Don't fail tests on React hydration errors
  if (err.message.includes('Hydration')) {
    return false
  }

  // Don't fail on network errors during tests
  if (err.message.includes('Network Error') || err.message.includes('fetch')) {
    return false
  }

  // Return false to prevent the error from failing the test
  // Return true (or don't return) to fail the test
  return false
})

// ============================================================================
// Custom Assertions
// ============================================================================

// Add custom chai assertions if needed
// chai.use((_chai, utils) => {
//   _chai.Assertion.addMethod('customMethod', function () {
//     // Custom assertion logic
//   })
// })

// ============================================================================
// Global Configuration
// ============================================================================

// Increase the default assertion timeout
Cypress.config('defaultCommandTimeout', 10000)

// Log all failed requests for debugging
Cypress.on('fail', (error, runnable) => {
  console.error('Test failed:', runnable.title)
  console.error('Error:', error.message)
  throw error
})
