export class LucairnError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'LucairnError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class LucairnConfigError extends LucairnError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'LucairnConfigError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class LucairnHttpError extends LucairnError {
  public readonly status: number;
  public readonly body: unknown;

  constructor(message: string, status: number, body: unknown, options?: ErrorOptions) {
    super(message, options);
    this.name = 'LucairnHttpError';
    this.status = status;
    this.body = body;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class LucairnTimeoutError extends LucairnError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'LucairnTimeoutError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export type VerifyCertificateFailureReason =
  | 'malformed'
  | 'unsupported_protocol_version'
  | 'witness_mismatch'
  | 'witness_signature_missing'
  | 'invalid_signature';

export interface LucairnCertificateErrorOptions extends ErrorOptions {
  reason: VerifyCertificateFailureReason;
  certificateId?: string;
}

export class LucairnCertificateError extends LucairnError {
  public readonly reason: VerifyCertificateFailureReason;

  /**
   * Certificate ID lifted from `cert.certificate_id` for error-context
   * logging. SECURITY NOTE: on all failure paths, this value is UNVERIFIED —
   * the witness signature has not yet been (or failed to) verify by the
   * time this ID is attached. An attacker or malformed cert can set any
   * string here. Consumers logging this field should treat it as untrusted
   * input (escape / truncate / bound length). Only on the success return
   * path (VerifyCertificateResult.certificateId) is this value covered by
   * the witness signature.
   */
  public readonly certificateId?: string;

  constructor(message: string, options: LucairnCertificateErrorOptions) {
    super(message, options);
    this.name = 'LucairnCertificateError';
    this.reason = options.reason;
    this.certificateId = options.certificateId;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// Legacy aliases — one minor-version migration cycle.
// Pre-Stage-3 callers imported `TheVeil*Error` names; these re-exports keep
// existing code compiling. Removal is scheduled for the next minor bump.
// ---------------------------------------------------------------------------
export {
  LucairnError as TheVeilError,
  LucairnConfigError as TheVeilConfigError,
  LucairnHttpError as TheVeilHttpError,
  LucairnTimeoutError as TheVeilTimeoutError,
  LucairnCertificateError as TheVeilCertificateError,
};
export type { LucairnCertificateErrorOptions as TheVeilCertificateErrorOptions };
