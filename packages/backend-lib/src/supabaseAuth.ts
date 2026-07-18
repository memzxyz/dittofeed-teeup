import { createDecoder } from "fast-jwt";
import { createRemoteJWKSet, jwtVerify } from "jose";
import type { JWTPayload } from "jose";
import config from "./config";
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

function getJwks() {
  if (!jwksCache) {
    const supabaseJwksUrl = config().supabaseJwksUrl;
    if (!supabaseJwksUrl) {
      throw new Error("SUPABASE_JWKS_URL not configured");
    }
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
    const { payload } = await jwtVerify(token, JWKS, {
      algorithms: ["RS256"],
    });

    const email = (payload.email as string) ?? "";
    if (!email) {
      logger().warn("Supabase JWT missing email claim");
      return null;
    }

    return {
      sub: payload.sub ?? "",
      email,
      email_verified:
        (payload.email_verified as boolean) ??
        (payload.email_confirmed_at !== undefined) ??
        false,
      name: (payload.name as string) ?? (payload.raw_user_meta_data as Record<string, unknown>)?.full_name as string ?? undefined,
      picture: (payload.picture as string) ?? undefined,
    };
  } catch (err) {
    logger().warn({ err }, "Supabase JWT verification failed");
    return null;
  }
}

export function decodeSupabaseJwt(token: string): Record<string, unknown> | null {
  try {
    const bearerToken = token.replace("Bearer ", "");
    const decoded = bearerToken ? decoder(bearerToken) : null;
    return decoded as Record<string, unknown> | null;
  } catch {
    return null;
  }
}
