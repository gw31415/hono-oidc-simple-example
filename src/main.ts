import { serve } from "@hono/node-server";
import { Hono } from "hono";
import {
  loginHandler,
  loginRequired,
  logoutHandler,
  useClaims,
} from "./auth.ts";

const app = new Hono();

///////////////////////////
// Login / Logout Routes
///////////////////////////

app.get("/login/google", loginHandler("https://accounts.google.com"));
app.get("/logout", logoutHandler);

///////////////////////////
// User Pages
///////////////////////////

app.get("/", useClaims, (c) => {
  return c.html(`<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home</title>
    </head>
    <body>
    <h1>Home</h1>
    ${
      c.get("claims")
        ? `<p>Hello, ${c.get("claims")?.sub}!</p><div><a href='/protected'>Protected Page</a></div><div><a href='/logout'>Logout</a></div>`
        : "<p>Nice to meet you!</p><div><a href='/login/google'>Login</a></div>"
    }
    </body>
  `);
});

app.get("/protected", loginRequired, (c) => {
  return c.html(`<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Protected</title>
    </head>
    <body>
    <h1>Protected</h1>
    <div><a href='/'>Home</a></div>
    </body>
  `);
});

serve({
  fetch: app.fetch,
  port: 3000,
});
