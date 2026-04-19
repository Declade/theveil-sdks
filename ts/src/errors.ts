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
