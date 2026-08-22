<?php

namespace SysHub\Passkey\Controllers;

use App\Http\Controllers\Controller;
use App\Events\UserLoggedIn;
use App\Models\User;
use Auth;
use SysHub\Passkey\Models\Passkey;
use SysHub\Passkey\Support\Base64Url;
use SysHub\Passkey\Support\ChallengeStore;
use SysHub\Passkey\Support\Requirements;
use SysHub\Passkey\Support\WebAuthnErrors;
use SysHub\Passkey\Support\WebAuthnFactory;
use Illuminate\Http\Request;

class LoginController extends Controller
{
    /**
     * Get login options (assertion)
     */
    public function options()
    {
        if ($failure = Requirements::failure()) {
            return $failure;
        }
        
        // Reject if already logged in
        if (Auth::check()) {
            return json(trans('SysHub\Passkey::messages.error.already_logged_in'), 1);
        }
        
        $webauthn = WebAuthnFactory::make();

        // Get assertion options (empty credential IDs for usernameless/discoverable).
        // lbuchs/WebAuthn getGetArgs signature:
        //   (credentialIds, timeout, allowUsb, allowNfc, allowBle, allowHybrid,
        //    allowInternal, requireUserVerification)
        // The UV level must be declared to the browser as well, otherwise the
        // options always say 'preferred' while processGet enforces 'required'
        // server-side — authenticators without UV capability would then always
        // fail with a generic error.
        $args = $webauthn->getGetArgs(
            [],
            60,
            true,
            true,
            true,
            true,
            true,
            WebAuthnFactory::getUserVerification()
        );
        
        // Store challenge in session
        ChallengeStore::put('login', $webauthn->getChallenge()->getBinaryString());
        
        return response()->json($args);
    }

    /**
     * Handle passkey login
     */
    public function login(Request $request)
    {
        if ($failure = Requirements::failure()) {
            return $failure;
        }
        
        // Reject if already logged in
        if (Auth::check()) {
            return json(trans('SysHub\Passkey::messages.error.already_logged_in'), 1);
        }
        
        // Validate and decode base64url fields. Use decodeInput(): a JSON null
        // or array in the request body must not reach decode(string), which
        // would throw a TypeError outside the try block below and surface as a
        // 500. Note that Request::input() returns null (not the default) when
        // the key exists with a null value, and BSS's global
        // ConvertEmptyStringsToNull middleware turns "" into null as well.
        $id = Base64Url::decodeInput($request->input('id'));
        $clientDataJSON = Base64Url::decodeInput($request->input('clientDataJSON'));
        $authenticatorData = Base64Url::decodeInput($request->input('authenticatorData'));
        $signature = Base64Url::decodeInput($request->input('signature'));

        if ($id === null || $clientDataJSON === null || $authenticatorData === null || $signature === null) {
            return json(trans('SysHub\Passkey::messages.error.invalid_data'), 1);
        }

        // userHandle is optional (absent for some non-discoverable credentials),
        // but when the client does send one it must be decodable.
        $rawUserHandle = $request->input('userHandle');
        $userHandle = Base64Url::decodeInput($rawUserHandle);
        if ($userHandle === null && is_string($rawUserHandle) && $rawUserHandle !== '') {
            return json(trans('SysHub\Passkey::messages.error.invalid_user_handle'), 1);
        }
        
        // Lookup passkey by credential ID hash
        $credentialIdHash = hash('sha256', $id);
        $passkey = Passkey::where('credential_id_hash', $credentialIdHash)->first();
        
        if (!$passkey) {
            return json(trans('SysHub\Passkey::messages.error.passkey_not_found'), 1);
        }
        
        // Decode stored public key (raw binary for processGet)
        $publicKey = Base64Url::decodeInput($passkey->public_key);
        if ($publicKey === null) {
            return json(trans('SysHub\Passkey::messages.error.authentication_failed'), 1);
        }
        
        // Get and consume the challenge this ceremony used (one-time use).
        $challenge = ChallengeStore::pop('login', $clientDataJSON);
        if ($challenge === null) {
            return json(trans('SysHub\Passkey::messages.error.invalid_challenge'), 1);
        }
        
        try {
            $webauthn = WebAuthnFactory::make();

            // Verify assertion. lbuchs/WebAuthn processGet signature:
            //   (clientDataJSON, authenticatorData, signature, credentialPublicKey,
            //    challenge, prevSignatureCnt, requireUserVerification,
            //    requireUserPresent)
            // Passing prevSignatureCnt also enables the library's own clone
            // detection: it throws SIGNATURE_COUNTER when the counter does not
            // advance, which is mapped to a specific message in the catch below.
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

            $newCounter = $webauthn->getSignatureCounter();

            // Get user
            $user = User::find($passkey->uid);
            
            if (!$user) {
                return json(trans('SysHub\Passkey::messages.error.user_not_found'), 1);
            }
            
            // Check if user is banned.
            // NOTE: BSS has no `status` column on `users`; the ban flag lives in
            // `permission` (User::BANNED === -1), which is what the core
            // RejectBannedUser middleware checks.
            if ((int) $user->permission === User::BANNED) {
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

            // Only record the counter and last-used time once the login is
            // actually granted: a rejected attempt should not look like a
            // successful sign-in in the management UI.
            if ($newCounter !== null && $newCounter > 0) {
                $passkey->counter = $newCounter;
            }
            $passkey->last_used_at = now();
            $passkey->save();

            // Dispatch events, mirroring the core password login so that
            // plugins listening on either the string events or the class event
            // (login statistics, IP logging, ...) also see passkey logins.
            $dispatcher = app('events');
            $dispatcher->dispatch('auth.login.ready', [$user]);

            $remember = filter_var(option('passkey_remember_login', true), FILTER_VALIDATE_BOOLEAN);
            Auth::login($user, $remember);

            $dispatcher->dispatch('auth.login.succeeded', [$user]);
            event(new UserLoggedIn($user));

            return json(trans('SysHub\Passkey::messages.login.success'), 0, [
                'redirectTo' => session()->pull('last_requested_path', url('/user')),
            ]);
            
        } catch (\Throwable $e) {
            $message = WebAuthnErrors::message($e, 'authentication_failed');
            if (config('app.debug')) {
                $message .= ': ' . get_class($e) . ': ' . $e->getMessage();
            }

            if (WebAuthnErrors::isClonedCredential($e)) {
                \Log::warning('[Passkey] Signature counter did not advance (possible cloned credential)', [
                    'passkey_id' => $passkey->id,
                    'stored_counter' => (int) $passkey->counter,
                ]);
            } else {
                \Log::error('[Passkey] Authentication failed', [
                    'exception' => $e,
                ]);
            }

            return json($message, 1);
        }
    }
}
