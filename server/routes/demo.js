/**
 * ============================================================
 *  DEMO-ONLY ROUTE — NOT PART OF THE PRODUCT API
 * ============================================================
 *
 * GET /api/demo/sms-otp
 *
 * Returns the simulated SMS code for the CALLER'S OWN active mobile
 * challenge, so the verification screen can display it during a demo.
 * Mounted only when DEMO_SMS_OTP=true and SMS_MODE=mock.
 *
 * Why this is safe to call from the browser without a token:
 *
 *   - The user is identified from the signed HttpOnly `reg_session`
 *     cookie, exactly like every other registration step. A userId in
 *     the query string would be ignored; there isn't one.
 *   - The SQL is scoped to that user_id, so you can only ever see a
 *     code minted for you. There is no parameter that could point at
 *     someone else's challenge.
 *   - It only returns an unconsumed, unexpired challenge, so it cannot
 *     be used to resurrect a dead code.
 *   - It is mock-only. With a real SMS provider configured the route is
 *     not mounted at all, because then the code genuinely reaches a
 *     phone and must never be echoed back.
 *
 * What it deliberately does NOT do: change how the OTP is generated,
 * hashed, expired, attempt-limited or consumed. POST /api/send-sms-otp
 * still never returns the code. This is a read-only side channel for
 * the demo, nothing more.
 */

const express = require("express");
const { queryOne } = require("../db/pool");
const { requireRegistrationSession } = require("../lib/auth");

const router = express.Router();

router.get("/sms-otp", requireRegistrationSession, async (req, res, next) => {
  try {
    const record = await queryOne(
      `select id, purpose, destination, test_otp, expires_at, attempts, max_attempts
         from otp_challenges
        where user_id = $1
          and channel = 'sms'
          and consumed = false
          and expires_at > now()
        order by created_at desc
        limit 1`,
      [req.user.id]
    );

    res.setHeader("Cache-Control", "no-store");

    if (!record) {
      return res.status(404).json({
        error: "no_active_challenge",
        message: "No active SMS code. Request one first.",
      });
    }

    if (!record.test_otp) {
      // Created while demo mode was off — only the hash exists.
      return res.status(409).json({
        error: "otp_not_recorded",
        message: "Request a new code to see it here.",
      });
    }

    return res.json({
      demo: true,
      otp: record.test_otp,
      destination: record.destination,
      expiresInMs: Math.max(0, new Date(record.expires_at).getTime() - Date.now()),
      attemptsLeft: record.max_attempts - record.attempts,
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
