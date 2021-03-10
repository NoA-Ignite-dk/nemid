interface Options {
  limit?: number;
  cleanup?: boolean;
}

declare module 'compare' {
  function compare(a: string, b: string): -1 | 0 | 1 

  export = compare ;
}