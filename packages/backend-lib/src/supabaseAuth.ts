import { createDecoder } from "fast-jwt";
import { createRemoteJWKSet, jwtVerify } from "jose";
import logger from "./logger";

const decoder = createDecoder();

export interface SupabaseUser {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  picture?: string;
}

let jwksCache: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJwksUrl(): string {
  const url = process.env.SUPABASE_JWKS_URL;
  if (!url) {
    throw new Error(
      "SUPABASE_JWKS_URL environment variable not set. " +
        "Example: https://project-ref.supabase.co/auth/v1/.well-known/jwks.json",
    );
  }
  return url;
}

function getJwks() {
  if (!jwksCache) {
    const supabaseJwksUrl = getJwksUrl();
    const url = new URL(supabaseJwksUrl);
    jwksCache = createRemoteJWKSet(url);
  }
  return jwksCache;
}

export function resetJwksCache() {
  jwksCache = null;
}

export async function verifySupabaseJwt(
  token: string,
): Promise<SupabaseUser | null> {
  try {
    const JWKS = getJwks();
    const bearerToken = token.replace(/^Bearer\s+/i, "");
    const { payload } = await jwtVerify(bearerToken, JWKS, {
      algorithms: ["RS256"],
    });

    const email = (payload.email as string) ?? "";
    if (!email) {
      logger().warn("Supabase JWT missing email claim");
      return null;
    }

    const userMeta = payload.raw_user_meta_data as Record<string, unknown> | undefined;

    return {
      sub: (payload.sub as string) ?? "",
      email,
      email_verified: (payload.email_verified as boolean) ?? false,
      name: (payload.name as string) ?? (userMeta?.full_name as string) ?? undefined,
      picture: (payload.picture as string) ?? undefined,
    };
  } catch (err) {
    logger().warn({ err }, "Supabase JWT verification failed");
    return null;
  }
}

export function decodeSupabaseJwtHeaders(
  token: string,
): Record<string, unknown> | null {
  try {
    const bearerToken = token.replace(/^Bearer\s+/i, "");
    const decoded = bearerToken ? decoder(bearerToken) : null;
    return decoded as Record<string, unknown> | null;
  } catch {
    return null;
  }
}
