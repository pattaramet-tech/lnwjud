import { describe, expect, it } from 'vitest';
import { updateStartupBlocksWritableStartup } from './host-native-authority.js';

describe('update startup gate', () => {
  it('blocks journaled transactions, slot selections and exact native package mismatch', () => {
    expect(updateStartupBlocksWritableStartup('UPDATE_NATIVE_PACKAGE_MISMATCH')).toBe(true);
    expect(updateStartupBlocksWritableStartup('UPDATE_NATIVE_PACKAGE_MISMATCH_UNKNOWN')).toBe(false);
    expect(updateStartupBlocksWritableStartup('UPDATE_TRANSACTION_PENDING')).toBe(true);
    expect(updateStartupBlocksWritableStartup('UPDATE_TRANSACTION_PUBLICATION_PENDING')).toBe(true);
    expect(updateStartupBlocksWritableStartup('UPDATE_SLOT_SELECTION_CONFLICT')).toBe(true);
    expect(updateStartupBlocksWritableStartup('UPDATE_TRANSACTION_COORDINATED_MAINTENANCE')).toBe(true);
    expect(updateStartupBlocksWritableStartup('UPDATE_TRANSACTION_COORDINATED_INSPECTION_UNAVAILABLE')).toBe(true);
  });

  it('lets the app open when no update authority is enrolled or the gate is unavailable', () => {
    expect(updateStartupBlocksWritableStartup('UPDATE_ENROLLMENT_UNVERIFIED')).toBe(false);
    expect(updateStartupBlocksWritableStartup('UPDATE_STARTUP_INSPECTION_UNAVAILABLE')).toBe(false);
    expect(updateStartupBlocksWritableStartup('MANUAL_INSTALLATION')).toBe(false);
  });
});
