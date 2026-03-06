// noinspection JSVoidFunctionReturnValueUsed

import { describe, expect, it } from '@jest/globals';
import { noopLogger } from '#utils/logger';

describe('noopLogger', () => {
  it('should have trace method that does nothing', () => {
    // GIVEN
    const testString = 'test message';
    const testObject = { key: 'value' };

    // WHEN & THEN - should not throw
    expect(() => noopLogger.trace(testString)).not.toThrow();
    expect(() => noopLogger.trace(testObject)).not.toThrow();
    expect(() => noopLogger.trace(testObject, testString)).not.toThrow();
  });

  it('should have debug method that does nothing', () => {
    // GIVEN
    const testString = 'test message';
    const testObject = { key: 'value' };

    // WHEN & THEN - should not throw
    expect(() => noopLogger.debug(testString)).not.toThrow();
    expect(() => noopLogger.debug(testObject)).not.toThrow();
    expect(() => noopLogger.debug(testObject, testString)).not.toThrow();
  });

  it('should have info method that does nothing', () => {
    // GIVEN
    const testString = 'test message';
    const testObject = { key: 'value' };

    // WHEN & THEN - should not throw
    expect(() => noopLogger.info(testString)).not.toThrow();
    expect(() => noopLogger.info(testObject)).not.toThrow();
    expect(() => noopLogger.info(testObject, testString)).not.toThrow();
  });

  it('should have warn method that does nothing', () => {
    // GIVEN
    const testString = 'test message';
    const testObject = { key: 'value' };

    // WHEN & THEN - should not throw
    expect(() => noopLogger.warn(testString)).not.toThrow();
    expect(() => noopLogger.warn(testObject)).not.toThrow();
    expect(() => noopLogger.warn(testObject, testString)).not.toThrow();
  });

  it('should have error method that does nothing', () => {
    // GIVEN
    const testString = 'test message';
    const testObject = { key: 'value' };

    // WHEN & THEN - should not throw
    expect(() => noopLogger.error(testString)).not.toThrow();
    expect(() => noopLogger.error(testObject)).not.toThrow();
    expect(() => noopLogger.error(testObject, testString)).not.toThrow();
  });

  it('should return undefined from all methods', () => {
    // GIVEN
    const testString = 'test message';

    // WHEN & THEN
    expect(noopLogger.trace(testString)).toBeUndefined();
    expect(noopLogger.debug(testString)).toBeUndefined();
    expect(noopLogger.info(testString)).toBeUndefined();
    expect(noopLogger.warn(testString)).toBeUndefined();
    expect(noopLogger.error(testString)).toBeUndefined();
  });
});
