const normalizeBaseUrl = (url: string) => url.replace(/\/$/, '');

// Safely read env vars — at build time these may be absent, so we
// fall back to an empty string rather than throwing. The real runtime
// error will surface when a client-side component tries to connect.
const socketUrl = process.env.NEXT_PUBLIC_SOCKET_URL ?? '';
const apiUrl = process.env.NEXT_PUBLIC_API_URL || socketUrl;

export const SOCKET_URL = normalizeBaseUrl(socketUrl);
export const API_BASE_URL = normalizeBaseUrl(apiUrl);

