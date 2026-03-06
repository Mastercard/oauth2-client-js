import { Logger } from '#types';

export const noopLogger: Logger = {
  trace: (..._args: any[]): void => {},
  debug: (..._args: any[]): void => {},
  info: (..._args: any[]): void => {},
  warn: (..._args: any[]): void => {},
  error: (..._args: any[]): void => {}
};
