<?php

namespace SysHub\Passkey\Support;

use lbuchs\WebAuthn\WebAuthn;

/**
 * Precondition checks shared by the controllers.
 *
 * The table check is memoized per request: every endpoint ran its own
 * `Schema::hasTable()` before, which costs a metadata query on each call even
 * though the answer cannot change mid-request.
 */
class Requirements
{
    private static ?bool $tableExists = null;

    /**
     * Returns an error response when a precondition fails, or null when the
     * plugin is ready to serve the request.
     */
    public static function failure()
    {
        if (!self::libraryInstalled()) {
            return json(trans('SysHub\Passkey::messages.error.webauthn_not_installed'), 1);
        }

        if (!self::tableExists()) {
            return json(trans('SysHub\Passkey::messages.error.table_not_found'), 1);
        }

        return null;
    }

    public static function libraryInstalled(): bool
    {
        return class_exists(WebAuthn::class);
    }

    public static function tableExists(): bool
    {
        if (self::$tableExists === null) {
            self::$tableExists = \Schema::hasTable('passkeys');
        }

        return self::$tableExists;
    }

    /**
     * Drop the memoized result. Only needed by tests.
     */
    public static function flush(): void
    {
        self::$tableExists = null;
    }
}
