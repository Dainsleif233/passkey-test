<?php

use App\Services\Hook;
use App\Services\Plugin;
use Blessing\Filter;
use Illuminate\Contracts\Events\Dispatcher;

return function (Filter $filter, Plugin $plugin, Dispatcher $events) {
    // Routes
    Hook::addRoute(function () {
        Route::namespace('SysHub\Passkey\Controllers')->group(__DIR__.'/routes.php');
    });

    // Login page button injection
    $filter->add('auth_page_rows:login', function ($rows) {
        if (filter_var(option('passkey_show_login_button', true), FILTER_VALIDATE_BOOLEAN)) {
            $length = count($rows);
            array_splice($rows, $length - 1, 0, ['SysHub\Passkey::login-button']);
        }
        return $rows;
    });

    // Load JS on auth/login and user/passkey pages
    Hook::addScriptFileToPage($plugin->assets('passkey.js'), ['auth/login', 'user/passkey']);

    // User menu item
    Hook::addMenuItem('user', 3, [
        'title' => 'SysHub\Passkey::general.title',
        'link'  => 'user/passkey',
        'icon'  => 'fa-fingerprint',
    ]);

    // Cleanup passkeys on user deletion
    $events->listen('user.deleted', function ($user) {
        \SysHub\Passkey\Models\Passkey::where('uid', $user->uid)->delete();
    });
};
