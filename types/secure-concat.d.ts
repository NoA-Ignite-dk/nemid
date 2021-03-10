interface Options {
  limit?: number;
  cleanup?: boolean;
}

declare module 'secure-concat' {
  type Callback = (err: any, res: Buffer) => void;

  function concat(cb: typeof Callback): WriteStream
  function concat(opts: Options, cb: typeof Callback): WriteStream

  export = concat;
}