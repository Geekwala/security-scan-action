const js = require('@eslint/js');
const tsParser = require('@typescript-eslint/parser');
const tsPlugin = require('@typescript-eslint/eslint-plugin');
const jestPlugin = require('eslint-plugin-jest');
const globals = require('globals');

module.exports = [
  {
    ignores: ['node_modules/**', 'dist/**', 'coverage/**', '__tests__/**']
  },
  {
    files: ['src/**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
        project: './tsconfig.json'
      },
      globals: {
        ...globals.node,
        NodeJS: 'readonly'
      }
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
      jest: jestPlugin
    },
    rules: {
      ...js.configs.recommended.rules,
      ...tsPlugin.configs.recommended.rules,
      ...jestPlugin.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }]
    }
  }
];
