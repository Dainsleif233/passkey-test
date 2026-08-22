<?php

namespace SysHub\Passkey\Support;

class Base64Url
{
    /**
     * Encode data to base64url
     */
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decode base64url to string, returns null on failure
     */
    public static function decode(string $data): ?string
    {
        $data = strtr($data, '-_', '+/');

        // Restore "=" padding: strict base64_decode rejects unpadded input
        // whose length is not a multiple of 4 (browsers strip padding).
        $remainder = strlen($data) % 4;
        if ($remainder === 2) {
            $data .= '==';
        } elseif ($remainder === 3) {
            $data .= '=';
        } elseif ($remainder === 1) {
            return null; // impossible length for valid base64
        }

        $data = base64_decode($data, true);

        if ($data === false) {
            return null;
        }

        return $data;
    }
}
