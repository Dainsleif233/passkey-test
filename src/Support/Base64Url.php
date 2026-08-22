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
     * Decode untrusted request input to base64url, returns null on failure.
     *
     * Request payloads can carry JSON null, arrays or objects for a field;
     * passing those to decode() would raise a TypeError (user-defined
     * functions never coerce null or arrays to string). Callers decode request
     * input before entering their try/catch block, so such an exception would
     * escape as a 500. Treat any non-string as invalid input instead.
     */
    public static function decodeInput(mixed $data): ?string
    {
        return is_string($data) ? self::decode($data) : null;
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
