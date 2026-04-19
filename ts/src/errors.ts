export class TheVeilError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TheVeilError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class TheVeilConfigError extends TheVeilError {
  constructor(message: string) {
    super(message);
    this.name = 'TheVeilConfigError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class TheVeilHttpError extends TheVeilError {
  public readonly status: number;
  public readonly body: unknown;

  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = 'TheVeilHttpError';
    this.status = status;
    this.body = body;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
