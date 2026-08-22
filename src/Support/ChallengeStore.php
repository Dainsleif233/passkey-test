<?php

namespace SysHub\Passkey\Support;

/**
 * Session backed store for one-time WebAuthn challenges.
 *
 * Several challenges of the same type can be pending at once: a user may have
 * the login page (or the manage page) open in two tabs, and each ceremony gets
 * its own challenge. A single session slot per type would let the second tab
 * overwrite the first one, so the older tab could never complete. Challenges are
 * therefore kept as a small keyed set, and the one actually used by the browser
 * is selected via the challenge echoed back inside clientDataJSON.
 */
class ChallengeStore
{
    private const TTL = 300; // 5 minutes

    /** Upper bound on concurrently pending challenges per type. */
    private const MAX_PENDING = 10;

    /**
     * Store a challenge, keyed by its own value so it can be matched later.
     */
    public static function put(string $type, string $challenge): void
    {
        $key = self::sessionKey($type);
        $pending = self::pending($key);

        $pending[Base64Url::encode($challenge)] = time() + self::TTL;

        // Keep the newest entries only, so a client looping over the options
        // endpoint cannot grow the session indefinitely.
        if (count($pending) > self::MAX_PENDING) {
            asort($pending);
            $pending = array_slice($pending, -self::MAX_PENDING, null, true);
        }

        session()->put($key, $pending);
    }

    /**
     * Retrieve and consume the challenge used by this ceremony (one-time use).
     *
     * When $clientDataJSON is given, the challenge it references is the one
     * consumed, leaving other pending challenges untouched. Without it (or when
     * it cannot be parsed) the newest pending challenge is consumed and all
     * others are dropped, matching the previous single-slot behaviour.
     */
    public static function pop(string $type, ?string $clientDataJSON = null): ?string
    {
        $key = self::sessionKey($type);
        $pending = self::pending($key);

        if ($pending === []) {
            session()->forget($key);

            return null;
        }

        $encoded = self::encodedChallengeFrom($clientDataJSON);

        if ($encoded !== null) {
            if (!array_key_exists($encoded, $pending)) {
                return null;
            }

            $expires = $pending[$encoded];
            unset($pending[$encoded]);

            if ($pending === []) {
                session()->forget($key);
            } else {
                session()->put($key, $pending);
            }

            return time() > $expires ? null : Base64Url::decode($encoded);
        }

        // No usable client data: fall back to the most recently issued one.
        session()->forget($key);
        asort($pending);
        $encoded = (string) array_key_last($pending);

        return time() > $pending[$encoded] ? null : Base64Url::decode($encoded);
    }

    private static function sessionKey(string $type): string
    {
        return "passkey_challenge_{$type}";
    }

    /**
     * Pending, non-expired challenges as [base64url challenge => expiry].
     */
    private static function pending(string $key): array
    {
        $stored = session()->get($key);

        // Migrate the legacy single-slot shape (['data' => ..., 'expires' => ...])
        // so sessions created before this change keep working.
        if (is_array($stored) && isset($stored['data'], $stored['expires']) && is_string($stored['data'])) {
            $stored = [$stored['data'] => $stored['expires']];
        }

        if (!is_array($stored)) {
            return [];
        }

        $now = time();
        $pending = [];
        foreach ($stored as $encoded => $expires) {
            if (is_string($encoded) && is_int($expires) && $expires >= $now) {
                $pending[$encoded] = $expires;
            }
        }

        return $pending;
    }

    /**
     * The challenge the browser signed, as stored (base64url), or null.
     */
    private static function encodedChallengeFrom(?string $clientDataJSON): ?string
    {
        if ($clientDataJSON === null || $clientDataJSON === '') {
            return null;
        }

        $data = json_decode($clientDataJSON, true);
        if (!is_array($data) || !isset($data['challenge']) || !is_string($data['challenge'])) {
            return null;
        }

        // clientDataJSON carries the challenge base64url encoded; normalise it
        // through decode/encode so padding differences cannot break the match.
        $binary = Base64Url::decode($data['challenge']);

        return $binary === null ? null : Base64Url::encode($binary);
    }
}
