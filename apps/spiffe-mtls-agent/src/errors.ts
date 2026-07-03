export class SpiffeError extends Error {
  readonly context: Record<string, unknown>;

  constructor(message: string, context: Record<string, unknown> = {}, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
    this.context = context;
  }
}

export class SpiffeAuthorizationError extends SpiffeError {}

export class SpiffeConfigurationError extends SpiffeError {}