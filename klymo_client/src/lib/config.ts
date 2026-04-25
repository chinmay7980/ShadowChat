const normalizeBaseUrl = (url: string) => url.replace(/\/$/, '');

function requireEnv(value: string | undefined, name: string): string {
  if (!value) {
    throw new Error(`${name} is required. Set it in your .env file.`);
  }
  return value;
}

const socketUrl = requireEnv(process.env.NEXT_PUBLIC_SOCKET_URL, 'NEXT_PUBLIC_SOCKET_URL');
const apiUrl = process.env.NEXT_PUBLIC_API_URL || socketUrl;

export const SOCKET_URL = normalizeBaseUrl(socketUrl);
export const API_BASE_URL = normalizeBaseUrl(apiUrl);
