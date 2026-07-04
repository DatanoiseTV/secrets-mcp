import { redact } from "./redact.js";
import type { Store } from "./store.js";
import { substitute } from "./template.js";

const BODY_CAP = 64 * 1024;

export interface HttpRequestOptions {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

export interface HttpResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
  secretsUsed: string[];
}

/**
 * Performs an HTTP request with {{vault:NAME}} placeholders resolved in the
 * URL, headers, and body. The response is redacted before it is returned, so
 * a reflected credential (echo endpoints, error messages quoting the auth
 * header) does not reach the model.
 */
export async function httpWithSecrets(
  store: Store,
  opts: HttpRequestOptions
): Promise<HttpResult> {
  const used = new Set<string>();
  const resolveText = (text: string): string => {
    const r = substitute(text, store);
    for (const name of r.used) used.add(name);
    return r.text;
  };

  const url = resolveText(opts.url);
  if (!/^https?:\/\//.test(url)) {
    throw new Error("vault_http only supports http(s) URLs");
  }
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(opts.headers ?? {})) {
    headers[k] = resolveText(v);
  }
  const body = opts.body !== undefined ? resolveText(opts.body) : undefined;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 60_000);
  let response: Response;
  try {
    response = await fetch(url, {
      method: opts.method ?? "GET",
      headers,
      body,
      signal: controller.signal,
      redirect: "manual",
    });
  } finally {
    clearTimeout(timer);
  }

  const secrets = store.allValues();
  const rawBody = await response.text();
  const redactedBody = redact(rawBody, secrets);
  const truncated = redactedBody.length > BODY_CAP;
  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((v, k) => {
    responseHeaders[k] = redact(v, secrets);
  });

  return {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
    body: truncated ? redactedBody.slice(0, BODY_CAP) + "\n[body truncated]" : redactedBody,
    truncated,
    secretsUsed: [...used],
  };
}
