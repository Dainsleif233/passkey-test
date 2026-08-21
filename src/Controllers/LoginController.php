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
        $uv = WebAuthnFactory::getUserVerification();
        
        // Get assertion options (empty credential IDs for usernameless/discoverable)
        $args = $webauthn->getGetArgs([], 60, true, true, true, true, true, $uv);
        
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
        
        // Get and consume challenge (one-time use)
        $challenge = ChallengeStore::pop('login');
        if ($challenge === null) {
            return json(trans('SysHub\Passkey::messages.error.invalid_challenge'), 1);
        }
        
        try {
            $webauthn = WebAuthnFactory::make();
            $uv = WebAuthnFactory::getUserVerification();
            
            // Verify assertion
            // Note: processGet 8th param is requireUserVerification
            // We check UV preference from config: 'required' enforces it, others don't
            $requireUV = ($uv === 'required');
            $result = $webauthn->processGet(
                $clientDataJSON,
                $authenticatorData,
                $signature,
                $passkey->public_key,
                $challenge,
                $passkey->counter,
                $uv,
                $requireUV
            );
            
            // Verify user handle if present (skip if null or empty)
            if ($userHandle !== null && $userHandle !== '') {
                $unpacked = unpack('J', $userHandle);
                if ($unpacked === false || (int) $unpacked['uid'] !== (int) $passkey->uid) {
                    return json(trans('SysHub\Passkey::messages.error.invalid_user_handle'), 1);
                }
            }
            
            // Update counter (only if new > 0)
            $newCounter = $webauthn->getSignatureCounter();
            if ($newCounter !== null && $newCounter > 0 && $newCounter > $passkey->counter) {
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
            
            // Dispatch events
            $dispatcher = app('events');
            $dispatcher->dispatch('auth.login.ready', [$user]);
            
            // Login the user
            Auth::login($user, (bool) option('passkey_remember_login', true));
            
            // Dispatch succeeded event
            $dispatcher->dispatch('auth.login.succeeded', [$user]);
            
            return json(trans('SysHub\Passkey::messages.login.success'), 0, [
                'redirectTo' => session()->pull('last_requested_path', url('/user')),
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