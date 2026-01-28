import { defineConfig } from 'cypress'

export default defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3000',
    specPattern: 'cypress/e2e/**/*.cy.{js,jsx,ts,tsx}',
    supportFile: 'cypress/support/e2e.ts',
    fixturesFolder: 'cypress/fixtures',
    screenshotsFolder: 'cypress/screenshots',
    videosFolder: 'cypress/videos',

    // Viewport settings
    viewportWidth: 1280,
    viewportHeight: 720,

    // Timeouts
    defaultCommandTimeout: 10000,
    requestTimeout: 10000,
    responseTimeout: 10000,
    pageLoadTimeout: 30000,

    // Retry configuration
    retries: {
      runMode: 2,
      openMode: 0,
    },

    // Video and screenshots
    video: false,
    screenshotOnRunFailure: true,

    // Environment variables
    env: {
      apiUrl: '/api/hsm',
      defaultUsername: 'admin',
      defaultPassword: 'dev',
    },

    setupNodeEvents(on, config) {
      // Implement node event listeners here if needed
      on('task', {
        log(message) {
          console.log(message)
          return null
        },
      })

      return config
    },
  },
})
