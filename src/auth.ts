import { OIDC, type OIDCMiddlewareType } from "@gw31415/hono-oidc-simple";
import { env } from "hono/adapter";
import { every } from "hono/combine";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { CookieOptions } from "hono/utils/cookie";
import { createRemoteJWKSet, jwtVerify } from "jose";

/** Cookie expiration date */
const COOKIE_MAXAGE = 60 * 60 * 24 * 30 * 6; // 6 months
// NOTE: This library assumes that id_token and refresh_token have roughly the same storage period.
// This is because the Issuer URL to whom the refresh_token is requested is identified from the data in id_token.
// Since the signature validity period of id_token is short, the storage period itself can be long.

/** List of corresponding Issuer */
type Issuers = "https://accounts.google.com";

const oidc = OIDC((c) => {
  const envs = env<{
    OIDC_GOOGLE_CLIENT: string;
    OIDC_GOOGLE_SECRET: string;
  }>(c);
  return {
    issuers: [
      {
        issuer: "https://accounts.google.com",
        authEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenEndpoint: "https://www.googleapis.com/oauth2/v4/token",
        tokenRevocationEndpoint: "https://oauth2.googleapis.com/revoke",
        jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
        clientId: envs.OIDC_GOOGLE_CLIENT,
        clientSecret: envs.OIDC_GOOGLE_SECRET,
        useLocalJwt: false,

        // NOTE: The type of the Claims is automatically set same as this function's result type.
        createClaims: async (c, tokens) => {
          const idToken: string | undefined = await tokens.getIDToken(c);
          if (idToken) {
            const jwks = createRemoteJWKSet(
              new URL("https://www.googleapis.com/oauth2/v3/certs"),
            );
            try {
              const { payload } = await jwtVerify(idToken, jwks, {
                issuer: "https://accounts.google.com",
                audience: envs.OIDC_GOOGLE_CLIENT,
              });
              return {
                sub: payload.sub,
              };
            } catch (e) {
              console.error(e);
            }
          }
          return undefined;
        },
        scopes: ["openid"],
      },
    ],
    getIssUrl: () => "https://accounts.google.com",
    clientSideTokenStore: {
      getRefreshToken: () => getCookie(c, "refresh_token"),
      setRefreshToken: (c, token) => {
        if (!token) {
          deleteCookie(c, "refresh_token");
          return;
        }
        const reqUrl = new URL(c.req.url);
        const opts: CookieOptions = {
          path: "/",
          sameSite: "Lax",
          httpOnly: true,
          secure: reqUrl.hostname !== "localhost",
          maxAge: COOKIE_MAXAGE,
        };
        setCookie(c, "refresh_token", token, opts);
      },
      getIDToken: () => getCookie(c, "id_token"),
      setIDToken: (c, keys) => {
        if (!keys) {
          deleteCookie(c, "id_token");
          return;
        }
        const cancelErr = new Error("Canceled");
        try {
          if (!keys) throw cancelErr;

          const reqUrl = new URL(c.req.url);
          const secure = reqUrl.hostname !== "localhost";
          return setCookie(c, "id_token", keys, {
            path: "/",
            sameSite: "Lax",
            httpOnly: true,
            secure,
            maxAge: COOKIE_MAXAGE,
          });
        } catch (e) {
          if (e !== cancelErr) throw e;
          deleteCookie(c, "id_token");
          deleteCookie(c, "refresh_token");
          return;
        }
      },
    },
  };
});

/** The type of the middleware of `oidc` */
type Middleware = OIDCMiddlewareType<typeof oidc>;

/** Tool to get the Claims */
export const useClaims = oidc.useClaims;

/** Middleware that specifies pages requiring login */
export const loginRequired: Middleware = every(oidc.useClaims, (async (
  c,
  next,
) => {
  if (!c.get("claims")) {
    return c.text("Unauthorized", 401);
  }
  return await next();
}) satisfies Middleware);

/** Handler to login and redirect to the top page */
export const loginHandler = (iss: Issuers) =>
  oidc.loginHandler(iss, (_res, c) => c.redirect("/"));

/** Handler to logout and redirect to the top page */
export const logoutHandler = oidc.logoutHandler((c) => c.redirect("/"));
