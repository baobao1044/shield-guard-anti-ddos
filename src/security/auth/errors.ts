export class AuthConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthConfigurationError';
  }
}

export class AuthVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthVerificationError';
  }
}
