import { betterAuth } from "better-auth";
import { bearer } from "better-auth/plugins";
import { kyselyAdapter } from "@better-auth/kysely-adapter";
import { Kysely, PostgresDialect } from "kysely";
import { pool } from "./db.js";

// Kysely wraps the existing pg Pool so Better Auth talks to the same database.
const db = new Kysely({
    dialect: new PostgresDialect({ pool }),
});

export const auth = betterAuth({
    database: kyselyAdapter(db, {
        provider: "pg",
    }),

    // Email + password sign-up/sign-in. Email verification is off for V1;
    // plug an email provider into `emailVerification.sendVerificationEmail`
    // (e.g. Resend) when you want to require it.
    emailAndPassword: {
        enabled: true,
        requireEmailVerification: false,
    },

    // Keep the CTD business user row in sync with the auth user.
    // Runs right after Better Auth creates its own `user` record.
    databaseHooks: {
        user: {
            create: {
                after: async (user) => {
                    await pool.query(
                        `INSERT INTO users (auth_user_id, full_name, email, status)
                         VALUES ($1, $2, $3, 'active')
                         ON CONFLICT (auth_user_id) DO NOTHING`,
                        [user.id, user.name, user.email]
                    );
                },
            },
        },
    },

    // Mobile apps (CT Data) authenticate with a bearer token instead of
    // cookies: sign-in returns it in the "set-auth-token" response header and
    // the app sends "Authorization: Bearer <token>".
    plugins: [bearer()],

    // Frontend origin(s) allowed to use the auth endpoints (cookies).
    trustedOrigins: process.env.FRONTEND_URL
        ? process.env.FRONTEND_URL.split(",").map((u) => u.trim())
        : [],
});
