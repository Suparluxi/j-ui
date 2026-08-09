export interface ApiError {
  code: string;
  message: string;
  details?: unknown;
}

let csrfToken = "";

export function setCSRF(token: string): void {
  csrfToken = token;
}

export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body) headers.set("Content-Type", "application/json");
  if (csrfToken && !["GET", "HEAD"].includes(options.method ?? "GET")) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  if (response.status === 204) return undefined as T;
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    throw (body ?? { code: "request_failed", message: `请求失败 (${response.status})` }) as ApiError;
  }
  return body as T;
}

export async function download(path: string, filename: string): Promise<void> {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "X-CSRF-Token": csrfToken }
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ message: "下载失败" }));
    throw body as ApiError;
  }
  const objectURL = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = objectURL;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(objectURL);
}
