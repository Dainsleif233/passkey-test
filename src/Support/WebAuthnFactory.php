<?php

namespace SysHub\Passkey\Support;

use lbuchs\WebAuthn\WebAuthn;

class WebAuthnFactory
{
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
     * Get user verification level from options
     */
    public static function getUserVerification(): bool|string
    {
        return option('passkey_user_verification', 'preferred');
    }
}