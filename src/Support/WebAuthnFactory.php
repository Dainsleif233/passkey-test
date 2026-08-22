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
     * Get user verification level from options ("preferred"|"required"|"discouraged").
     *
     * Pass this to getCreateArgs()/getGetArgs(): those accept the raw string and
     * forward it to the browser, so all three configured levels stay
     * distinguishable.
     */
    public static function getUserVerification(): string
    {
        $uv = option('passkey_user_verification', 'preferred');

        return in_array($uv, self::UV_LEVELS, true) ? $uv : 'preferred';
    }

    /**
     * Whether the server must reject an assertion/attestation without the UV flag.
     *
     * Only for processCreate()/processGet(): those evaluate the parameter for
     * truthiness, so the raw option string must never be passed there (any
     * non-empty string would silently force "required"). Both "preferred" and
     * "discouraged" mean "do not enforce" on the server side.
     */
    public static function requireUserVerification(): bool
    {
        return self::getUserVerification() === 'required';
    }
}
