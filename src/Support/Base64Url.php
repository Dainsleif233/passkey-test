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
        $data = base64_decode($data, true);
        
        if ($data === false) {
            return null;
        }
        
        return $data;
    }
}
