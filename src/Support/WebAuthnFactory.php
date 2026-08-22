<?php

namespace SysHub\Passkey\Support;

use lbuchs\WebAuthn\WebAuthn;

class WebAuthnFactory
{
    public const UV_LEVELS = ['preferred', 'required', 'discouraged'];

    /**
     * Create a WebAuthn instance with configuration from options
     */
    public static function make(): WebAuthn
    {
        $rpId = option('passkey_rp_id', '') ?: request()->getHost();
        $rpName = option('passkey_rp_name', '') ?: option_localized('site_name');

        return new WebAuthn($rpName, $rpId, null, true);
    }

    /**
     * Get user verification level from options ("preferred"|"required"|"discouraged")
     */
    public static function getUserVerification(): string
    {
        $uv = option('passkey_user_verification', 'preferred');

        return in_array($uv, self::UV_LEVELS, true) ? $uv : 'preferred';
    }

    /**
     * The lbuchs/WebAuthn library expects a BOOLEAN for user verification.
     * Never pass the raw option string: any non-empty string is truthy in PHP,
     * which would silently force "required".
     */
    public static function requireUserVerification(): bool
    {
        return self::getUserVerification() === 'required';
    }
}
