import { describe, expect, it } from 'vitest';
import { parseField } from './Actions';
describe('catalog form values', () => {
  it('retains false and zero as explicit values', () => {
    expect(parseField({ name: 'analyze', kind: 'bool' }, 'false')).toBe(false);
    expect(parseField({ name: 'offset', kind: 'int', required: true }, '0')).toBe(0);
  });
  it('omits an unset optional override', () => { expect(parseField({ name: 'output' }, '')).toBeUndefined(); });
  it('requires a named missing value', () => { expect(() => parseField({ name: 'program', required: true }, '')).toThrow('program is required'); });
  it('rejects fractional integers and nonfinite numeric inputs', () => {
    expect(() => parseField({ name: 'attempts', kind: 'int' }, '2.5')).toThrow('whole number');
    expect(() => parseField({ name: 'timeout', kind: 'float' }, 'Infinity')).toThrow('number');
  });
  it('parses object and list inputs without evaluating source', () => {
    expect(parseField({ name: 'types', kind: 'object' }, '{"size":4}')).toEqual({ size: 4 });
    expect(parseField({ name: 'targets', kind: 'array' }, '["main"]')).toEqual(['main']);
    expect(() => parseField({ name: 'types', kind: 'object' }, '[]')).toThrow('JSON');
    expect(() => parseField({ name: 'targets', kind: 'array' }, '{"addr":1}')).toThrow('JSON');
  });
});
