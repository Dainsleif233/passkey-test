<?php

namespace SysHub\Passkey\Controllers;

use App\Http\Controllers\Controller;
use Option;

class ConfigController extends Controller
{
    public function render()
    {
        $form = Option::form('passkey', trans('SysHub\Passkey::config.title'), function ($form) {
            $form->text('passkey_rp_id', trans('SysHub\Passkey::config.rp_id.title'))
                ->description(trans('SysHub\Passkey::config.rp_id.description'))
                ->placeholder('example.com');

            $form->text('passkey_rp_name', trans('SysHub\Passkey::config.rp_name.title'))
                ->description(trans('SysHub\Passkey::config.rp_name.description'))
                ->placeholder(trans('SysHub\Passkey::config.rp_name.placeholder'));

            $form->select('passkey_user_verification', trans('SysHub\Passkey::config.user_verification.title'))
                ->description(trans('SysHub\Passkey::config.user_verification.description'))
                ->option('preferred', 'Preferred')
                ->option('required', 'Required')
                ->option('discouraged', 'Discouraged');

            $form->checkbox('passkey_show_login_button', trans('SysHub\Passkey::config.show_login_button.title'))
                ->label(trans('SysHub\Passkey::config.show_login_button.description'));

            $form->checkbox('passkey_remember_login', trans('SysHub\Passkey::config.remember_login.title'))
                ->label(trans('SysHub\Passkey::config.remember_login.description'));

            $form->text('passkey_max_passkeys', trans('SysHub\Passkey::config.max_passkeys.title'))
                ->description(trans('SysHub\Passkey::config.max_passkeys.description'));
        })->handle();

        return view('SysHub\Passkey::config', compact('form'));
    }
}