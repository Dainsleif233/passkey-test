<?php

use Illuminate\Routing\Middleware\SubstituteBindings;

// Auth passkey routes (guest access)
Route::prefix('auth/passkey')
    ->middleware(['web'])
    ->group(function () {
        Route::get('options', 'LoginController@options')
            ->middleware('throttle:20,1');
        Route::post('login', 'LoginController@login')
            ->middleware('throttle:10,1');
    });

// User passkey management (verified user)
Route::prefix('user/passkey')
    ->middleware('verified')
    ->group(function () {
        Route::get('', 'PasskeyController@index');
        Route::get('create-options', 'PasskeyController@createOptions')
            ->middleware('throttle:10,1');
        Route::post('', 'PasskeyController@register')
            ->middleware('throttle:10,1');
        Route::put('{passkey}', 'PasskeyController@rename')
            ->middleware(SubstituteBindings::class)
            ->middleware('throttle:30,1');
        Route::delete('{passkey}', 'PasskeyController@delete')
            ->middleware(SubstituteBindings::class)
            ->middleware('throttle:30,1');
    });
