<?php

use App\Events\PluginWasEnabled;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;

return [
    PluginWasEnabled::class => function () {
        if (!Schema::hasTable('passkeys')) {
            Schema::create('passkeys', function (Blueprint $table) {
                $table->bigIncrements('id');
                $table->unsignedBigInteger('uid');
                $table->string('name', 64)->default('');
                $table->text('credential_id');
                $table->char('credential_id_hash', 64)->unique();
                $table->text('public_key');
                $table->string('attestation_format', 32)->default('none');
                $table->string('aaguid', 36)->default('');
                $table->unsignedBigInteger('counter')->default(0);
                $table->timestamps();
                $table->timestamp('last_used_at')->nullable();

                $table->index('uid');
            });
        }

        // Set default options
        $defaults = [
            'passkey_rp_id' => '',
            'passkey_rp_name' => '',
            'passkey_user_verification' => 'preferred',
            'passkey_show_login_button' => 'true',
            'passkey_remember_login' => 'true',
            'passkey_max_passkeys' => '5',
        ];

        foreach ($defaults as $key => $value) {
            if (option($key, null, true) === null) {
                option([$key => $value]);
            }
        }
    },
];