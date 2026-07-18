import { createDecoder } from "fast-jwt";
import logger from "./logger";

const decoder = createDecoder();

export interface SupabaseUser {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  picture?: string;
}

export async function verifySupabaseJwt(
  token: string,
): Promise<SupabaseUser | null> {
  try {
    const bearerToken = token.replace(/^Bearer\s+/i, "");
    const decoded: Record<string, unknown> | null = bearerToken
      ? (decoder(bearerToken) as Record<string, unknown>)
      : null;

    if (!decoded) {
      logger().warn("Supabase JWT decode failed");
      return null;
    }

    const email = (decoded.email as string) ?? "";
    if (!email) {
      logger().warn("Supabase JWT missing email claim");
      return null;
    }

    const userMeta = decoded.raw_user_meta_data as Record<string, unknown> | undefined;
    const appMeta = decoded.app_metadata as Record<string, unknown> | undefined;

    return {
      sub: (decoded.sub as string) ?? "",
      email,
      email_verified: (decoded.email_verified as boolean) ?? (appMeta?.email_verified as boolean) ?? false,
      name: (decoded.name as string) ?? (userMeta?.full_name as string) ?? undefined,
      picture: (decoded.picture as string) ?? undefined,
    };
  } catch (err) {
    logger().warn({ err }, "Supabase JWT decode failed");
    return null;
  }
}
