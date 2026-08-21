<?php

namespace SysHub\Passkey\Support;

class ChallengeStore
{
    private const TTL = 300; // 5 minutes

    /**
     * Store a challenge with expiration
     */
    public static function put(string $type, string $challenge): void
    {
        $key = "passkey_challenge_{$type}";
        $data = [
            'data' => Base64Url::encode($challenge),
            'expires' => time() + self::TTL,
        ];
        
        session()->put($key, $data);
    }

    /**
     * Retrieve and consume a challenge (one-time use)
     */
    public static function pop(string $type): ?string
    {
        $key = "passkey_challenge_{$type}";
        $data = session()->pull($key);
        
        if ($data === null) {
            return null;
        }
        
        if (time() > $data['expires']) {
            return null;
        }
        
        return Base64Url::decode($data['data']);
    }
}