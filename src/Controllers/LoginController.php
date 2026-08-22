<?php

namespace SysHub\Passkey\Controllers;

use App\Http\Controllers\Controller;
use App\Models\User;
use Auth;
use SysHub\Passkey\Models\Passkey;
use SysHub\Passkey\Support\Base64Url;
use SysHub\Passkey\Support\ChallengeStore;
use SysHub\Passkey\Support\WebAuthnFactory;
use lbuchs\WebAuthn\WebAuthn;
use Illuminate\Http\Request;

class LoginController extends Controller
{
    /**
     * Get login options (assertion)
     */
    public function options()
    {
        // Precondition checks
        if (!class_exists(WebAuthn::class)) {
            return json(trans('SysHub\Passkey::messages.error.webauthn_not_installed'), 1);
        }
        
        if (!\Schema::hasTable('passkeys')) {
            return json(trans('SysHub\Passkey::messages.error.table_not_found'), 1);
        }
        
        // Reject if already logged in
        if (Auth::check()) {
            return json(trans('SysHub\Passkey::messages.error.already_logged_in'), 1);
        }
        
        $webauthn = WebAuthnFactory::make();

        // Get assertion options (empty credential IDs for usernameless/discoverable).
        // UV is enforced server-side in processGet; do not pass the raw option
        // string here — lbuchs/WebAuthn expects booleans.
        $args = $webauthn->getGetArgs([], 60);
        
        // Store challenge in session
        ChallengeStore::put('login', $webauthn->getChallenge()->getBinaryString());
        
        return response()->json($args);
    }

    /**
     * Handle passkey login
     */
    public function login(Request $request)
    {
        // Precondition checks
        if (!class_exists(WebAuthn::class)) {
            return json(trans('SysHub\Passkey::messages.error.webauthn_not_installed'), 1);
        }
        
        if (!\Schema::hasTable('passkeys')) {
            return json(trans('SysHub\Passkey::messages.error.table_not_found'), 1);
        }
        
        // Reject if already logged in
        if (Auth::check()) {
            return json(trans('SysHub\Passkey::messages.error.already_logged_in'), 1);
        }
        
        // Validate and decode base64url fields
        $id = Base64Url::decode($request->input('id', ''));
        $clientDataJSON = Base64Url::decode($request->input('clientDataJSON', ''));
        $authenticatorData = Base64Url::decode($request->input('authenticatorData', ''));
        $signature = Base64Url::decode($request->input('signature', ''));
        $userHandle = Base64Url::decode($request->input('userHandle', ''));
        
        if ($id === null || $clientDataJSON === null || $authenticatorData === null || $signature === null) {
            return json(trans('SysHub\Passkey::messages.error.invalid_data'), 1);
        }
        
        // Lookup passkey by credential ID hash
        $credentialIdHash = hash('sha256', $id);
        $passkey = Passkey::where('credential_id_hash', $credentialIdHash)->first();
        
        if (!$passkey) {
            return json(trans('SysHub\Passkey::messages.error.passkey_not_found'), 1);
        }
        
        // Decode stored public key (raw binary for processGet)
        $publicKey = Base64Url::decode($passkey->public_key);
        if ($publicKey === null) {
            return json(trans('SysHub\Passkey::messages.error.authentication_failed'), 1);
        }
        
        // Get and consume challenge (one-time use)
        $challenge = ChallengeStore::pop('login');
        if ($challenge === null) {
            return json(trans('SysHub\Passkey::messages.error.invalid_challenge'), 1);
        }
        
        try {
            $webauthn = WebAuthnFactory::make();

            // Verify assertion. lbuchs/WebAuthn processGet signature:
            //   (clientDataJSON, authenticatorData, signature, credentialPublicKey,
            //    challenge, previousCounter, requireUserVerification)
            $webauthn->processGet(
                $clientDataJSON,
                $authenticatorData,
                $signature,
                $publicKey,
                $challenge,
                (int) $passkey->counter,
                WebAuthnFactory::requireUserVerification()
            );

            // Verify user handle if present (skip if null or empty)
            if ($userHandle !== null && $userHandle !== '') {
                $unpacked = unpack('Juid', $userHandle);
                if ($unpacked === false || (int) $unpacked['uid'] !== (int) $passkey->uid) {
                    return json(trans('SysHub\Passkey::messages.error.invalid_user_handle'), 1);
                }
            }

            // Clone detection: reject the assertion when the signature counter
            // regresses (both values > 0 means this authenticator uses counters).
            $newCounter = $webauthn->getSignatureCounter();
            if ($newCounter !== null && $newCounter > 0
                && (int) $passkey->counter > 0 && $newCounter <= (int) $passkey->counter
            ) {
                \Log::warning('[Passkey] Signature counter regression (possible cloned credential)', [
                    'passkey_id' => $passkey->id,
                    'stored_counter' => (int) $passkey->counter,
                    'received_counter' => $newCounter,
                ]);
                return json(trans('SysHub\Passkey::messages.error.counter_regression'), 1);
            }

            if ($newCounter !== null && $newCounter > 0) {
                $passkey->counter = $newCounter;
            }
            
            // Update last used time
            $passkey->last_used_at = now();
            $passkey->save();
            
            // Get user
            $user = User::find($passkey->uid);
            
            if (!$user) {
                return json(trans('SysHub\Passkey::messages.error.user_not_found'), 1);
            }
            
            // Check if user is banned
            if ($user->status === User::BANNED) {
                return json(trans('SysHub\Passkey::messages.error.user_banned'), 1);
            }

            // Enforce email verification, same as password login (CheckUserVerified).
            // NOTE: BSS stores verification in its own `verified` boolean column,
            // NOT Laravel's email_verified_at. The base Authenticatable user does
            // provide hasVerifiedEmail(), but it reads the non-existent
            // email_verified_at column and would reject EVERY user.
            if ((bool) option('require_verification', false) && ! $user->verified) {
                return json(trans('SysHub\Passkey::messages.error.user_not_verified'), 1);
            }

            // Dispatch events
            $dispatcher = app('events');
            $dispatcher->dispatch('auth.login.ready', [$user]);

            $remember = filter_var(option('passkey_remember_login', true), FILTER_VALIDATE_BOOLEAN);
            Auth::login($user, $remember);

            // Dispatch succeeded event
            $dispatcher->dispatch('auth.login.succeeded', [$user]);

            // Explicit response shape: BSS's json() helper's third argument is
            // headers, not payload — build the JSON ourselves so the frontend
            // reliably receives data.redirectTo.
            return response()->json([
                'code' => 0,
                'message' => trans('SysHub\Passkey::messages.login.success'),
                'data' => [
                    'redirectTo' => session()->pull('last_requested_path', url('/user')),
                ],
            ]);
            
        } catch (\Throwable $e) {
            $message = trans('SysHub\Passkey::messages.error.authentication_failed');
            if (config('app.debug')) {
                $message .= ': ' . get_class($e) . ': ' . $e->getMessage();
            }
            \Log::error('[Passkey] Authentication failed', [
                'exception' => $e,
            ]);
            return json($message, 1);
        }
    }
}
