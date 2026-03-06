export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',

  // Module and path mappings
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json'],
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      useESM: true,
      tsconfig: 'tests/tsconfig.json',
      sourceMap: true,
      inlineSourceMap: true,
      inlineSources: true
    }],
    '^.+\\.jsx?$': ['babel-jest', {
      presets: [
        ['@babel/preset-env', { targets: { node: 'current' } }]
      ]
    }]
  },
  transformIgnorePatterns: [
    '/node_modules/(?!(@babel|msw|@mswjs|until-async)/)'
  ],

  // Test file patterns
  testMatch: [
    '**/src/**/*.test.(ts|tsx|js)',
    '**/tests/**/*.test.(ts|tsx|js)',
    '**/__tests__/**/*.(ts|tsx|js)'
  ],

  // Coverage configuration
  collectCoverage: false,
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'json', 'html'],
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/index.ts'
  ],

  // ESM support
  extensionsToTreatAsEsm: ['.ts'],

  // Global setup for crypto and other Web APIs
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],

  // Module name mapping - map to source files for debugging
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
    '^@mastercard/oauth2-client-js$': '<rootDir>/src/index.ts',
    '^#types$': '<rootDir>/src/types.ts',
    '^#core/(.*)$': '<rootDir>/src/core/$1',
    '^#crypto/(.*)$': '<rootDir>/src/crypto/$1',
    '^#http/(.*)$': '<rootDir>/src/http/$1',
    '^#security/(.*)$': '<rootDir>/src/security/$1',
    '^#utils/(.*)$': '<rootDir>/src/utils/$1',
    '^#tokens/(.*)$': '<rootDir>/src/tokens/$1',
    '^#scope/(.*)$': '<rootDir>/src/scope/$1',
    '^#mock-server/(.*)$': '<rootDir>/tests/integration/e2e/_mock_server_/$1',
    '^#test-utils/(.*)$': '<rootDir>/tests/_utils_/$1'
  },

  // Timeout
  testTimeout: 15000
};
