export class TheVeilError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'TheVeilError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class TheVeilConfigError extends TheVeilError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'TheVeilConfigError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class TheVeilHttpError extends TheVeilError {
  public readonly status: number;
  public readonly body: unknown;

  constructor(message: string, status: number, body: unknown, options?: ErrorOptions) {
    super(message, options);
    this.name = 'TheVeilHttpError';
    this.status = status;
    this.body = body;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class TheVeilTimeoutError extends TheVeilError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'TheVeilTimeoutError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export type VerifyCertificateFailureReason =
  | 'malformed'
  | 'unsupported_protocol_version'
  | 'witness_mismatch'
  | 'witness_signature_missing'
  | 'invalid_signature';

export interface TheVeilCertificateErrorOptions extends ErrorOptions {
  reason: VerifyCertificateFailureReason;
  certificateId?: string;
}

export class TheVeilCertificateError extends TheVeilError {
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

  constructor(message: string, options: TheVeilCertificateErrorOptions) {
    super(message, options);
    this.name = 'TheVeilCertificateError';
    this.reason = options.reason;
    this.certificateId = options.certificateId;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
