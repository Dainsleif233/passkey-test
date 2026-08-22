<?php

namespace SysHub\Passkey\Support;

use lbuchs\WebAuthn\WebAuthnException;

/**
 * Maps lbuchs/WebAuthn failures onto the plugin's own error messages.
 *
 * The library signals every verification failure with a WebAuthnException whose
 * code identifies the exact step that failed. Without this mapping every
 * failure collapses into one generic message, and specific wording (such as the
 * cloned-credential warning) can never be shown.
 */
class WebAuthnErrors
{
    /**
     * Translate a caught throwable into a user facing message.
     *
     * @param string $fallbackKey message key used for anything unrecognized
     */
    public static function message(\Throwable $e, string $fallbackKey): string
    {
        $key = self::keyFor($e) ?? $fallbackKey;

        return trans('SysHub\Passkey::messages.error.'.$key);
    }

    /**
     * The signature counter went backwards, which the spec flags as a possible
     * cloned authenticator. Worth a louder log line than an ordinary failure.
     */
    public static function isClonedCredential(\Throwable $e): bool
    {
        return $e instanceof WebAuthnException
            && $e->getCode() === WebAuthnException::SIGNATURE_COUNTER;
    }

    /**
     * Message key for a library failure, or null when there is no specific one.
     */
    private static function keyFor(\Throwable $e): ?string
    {
        // instanceof against a missing class is simply false, so the library
        // constants below are only touched once we know it is loaded.
        if (!$e instanceof WebAuthnException) {
            return null;
        }

        $keys = [
            WebAuthnException::INVALID_DATA => 'invalid_data',
            WebAuthnException::INVALID_TYPE => 'invalid_data',
            WebAuthnException::INVALID_CHALLENGE => 'invalid_challenge',
            WebAuthnException::INVALID_ORIGIN => 'invalid_origin',
            WebAuthnException::INVALID_RELYING_PARTY => 'invalid_relying_party',
            WebAuthnException::INVALID_SIGNATURE => 'invalid_signature',
            WebAuthnException::INVALID_PUBLIC_KEY => 'invalid_public_key',
            WebAuthnException::CERTIFICATE_NOT_TRUSTED => 'certificate_not_trusted',
            WebAuthnException::USER_PRESENT => 'user_not_present',
            WebAuthnException::USER_VERIFICATED => 'user_verification_failed',
            WebAuthnException::SIGNATURE_COUNTER => 'counter_regression',
            WebAuthnException::ANDROID_NOT_TRUSTED => 'android_not_trusted',
        ];

        return $keys[$e->getCode()] ?? null;
    }
}
