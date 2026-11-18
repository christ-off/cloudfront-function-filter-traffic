import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    alias: {
      cloudfront: new URL('./test-support/cloudfront-stub.js', import.meta.url).pathname,
    },
  },
  test: {
    coverage: {
      provider: 'v8',
      reporter: ['lcov', 'text'],
      include: ['function.js'],
    },
  },
})
