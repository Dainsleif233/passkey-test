<?php

namespace SysHub\Passkey\Controllers;

use App\Http\Controllers\Controller;
use Auth;
use SysHub\Passkey\Models\Passkey;
use SysHub\Passkey\Support\Base64Url;
use SysHub\Passkey\Support\ChallengeStore;
use SysHub\Passkey\Support\WebAuthnFactory;
use lbuchs\WebAuthn\WebAuthn;
use Illuminate\Http\Request;

class PasskeyController extends Controller
{
    /**
     * Show passkey management page or return JSON list
     */
    public function index(Request $request)
    {
        $user = Auth::user();
        $passkeys = Passkey::where('uid', $user->uid)
            ->orderBy('created_at', 'desc')
            ->get();
        
        // Return JSON for AJAX requests
        if ($request->expectsJson() || $request->ajax()) {
            return response()->json([
                'code' => 0,
                'message' => 'ok',
                'data' => $passkeys->map(function ($pk) {
                    return [
                        'id' => $pk->id,
                        'name' => $pk->name,
                        'created_at' => $pk->created_at,
                        'last_used_at' => $pk->last_used_at,
                    ];
                }),
            ]);
        }
        
        return view('SysHub\Passkey::manage', compact('passkeys'));
    }

    /**
     * Get creation options for new passkey
     */
    public function createOptions()
    {
        // Precondition checks
        if (!class_exists(WebAuthn::class)) {
            return json(trans('SysHub\Passkey::messages.error.webauthn_not_installed'), 1);
        }
        
        if (!\Schema::hasTable('passkeys')) {
            return json(trans('SysHub\Passkey::messages.error.table_not_found'), 1);
        }
        
        $user = Auth::user();
        $webauthn = WebAuthnFactory::make();

        // Get existing credential IDs to exclude
        $excludeIds = Passkey::where('uid', $user->uid)
            ->pluck('credential_id')
            ->map(function ($credentialId) {
                return Base64Url::decode($credentialId);
            })
            ->filter()
            ->values()
            ->all();

        // lbuchs/WebAuthn v2 getCreateArgs signature:
        //   (userId, userName, userDisplayName, timeout,
        //    requireResidentKey, requireUserVerification, excludeCredentials, extensions)
        // Resident keys are required for usernameless login; UV must be a
        // boolean — never pass the raw option string (always truthy in PHP).
        $userId = pack('J', $user->uid);
        $args = $webauthn->getCreateArgs(
            $userId,
            $user->email,
            $user->nickname,
            60,
            true, // requireResidentKey: discoverable credential
            WebAuthnFactory::requireUserVerification(),
            $excludeIds
        );
        
        // Store challenge in session
        ChallengeStore::put('create', $webauthn->getChallenge()->getBinaryString());

        if (config('app.debug')) {
            $args->_debug = [
                'challenge_stored' => session()->has('passkey_challenge_create'),
            ];
        }

        return response()->json($args);
    }

    /**
     * Register a new passkey
     */
    public function register(Request $request)
    {
        // Precondition checks
        if (!class_exists(WebAuthn::class)) {
            return json(trans('SysHub\Passkey::messages.error.webauthn_not_installed'), 1);
        }
        
        if (!\Schema::hasTable('passkeys')) {
            return json(trans('SysHub\Passkey::messages.error.table_not_found'), 1);
        }
        
        $user = Auth::user();
        
        // Check max passkeys limit
        $maxPasskeys = max(1, (int) option('passkey_max_passkeys', 5));
        $currentCount = Passkey::where('uid', $user->uid)->count();
        
        if ($currentCount >= $maxPasskeys) {
            return json(trans('SysHub\Passkey::messages.error.max_passkeys_reached', ['max' => $maxPasskeys]), 1);
        }
        
        // Validate and decode base64url fields
        $clientDataJSON = Base64Url::decode($request->input('clientDataJSON', ''));
        $attestationObject = Base64Url::decode($request->input('attestationObject', ''));
        
        if ($clientDataJSON === null || $attestationObject === null) {
            return json(trans('SysHub\Passkey::messages.error.invalid_data'), 1);
        }
        
        // Get and consume challenge
        $challenge = ChallengeStore::pop('create');
        if ($challenge === null) {
            $msg = trans('SysHub\Passkey::messages.error.invalid_challenge');
            if (config('app.debug')) {
                $msg .= ' | session_key_exists: ' . (session()->has('passkey_challenge_create') ? 'yes' : 'no');
                \Log::debug('[Passkey] Challenge missing', [
                    'session_id' => session()->getId(),
                    'session_driver' => config('session.driver'),
                ]);
            }
            return json($msg, 1);
        }
        
        try {
            $webauthn = WebAuthnFactory::make();

            // Verify attestation. lbuchs/WebAuthn v2 processCreate signature:
            //   (clientDataJSON, attestationObject, challenge,
            //    requireUserVerification, requireResidentKey,
            //    failIfRootMismatch, requireCtsProfileMatch)
            $result = $webauthn->processCreate(
                $clientDataJSON,
                $attestationObject,
                $challenge,
                WebAuthnFactory::requireUserVerification(),
                true,  // requireResidentKey (must match createOptions)
                false, // failIfRootMismatch = false
                false  // requireCtsProfileMatch = false
            );
            
            // Get and validate passkey name
            $name = trim($request->input('name', ''));
            if ($name === '') {
                $name = 'Passkey ' . ($currentCount + 1);
            }
            
            // Validate name length (DB column is string(64))
            if (mb_strlen($name) > 64) {
                return json(trans('SysHub\Passkey::messages.error.name_too_long'), 1);
            }
            
            // Store passkey
            $credentialId = $result->credentialId;
            $credentialIdBinary = is_string($credentialId)
                ? $credentialId
                : $credentialId->getBinaryString();

            $credentialIdHash = hash('sha256', $credentialIdBinary);

            // Friendly error for duplicate registration (unique index would
            // otherwise surface as a generic QueryException below).
            if (Passkey::where('credential_id_hash', $credentialIdHash)->exists()) {
                return json(trans('SysHub\Passkey::messages.error.credential_exists'), 1);
            }

            $passkey = new Passkey();
            $passkey->uid = $user->uid;
            $passkey->name = $name;
            $passkey->credential_id = Base64Url::encode($credentialIdBinary);
            $passkey->credential_id_hash = $credentialIdHash;
            $publicKey = $result->credentialPublicKey;
            $passkey->public_key = Base64Url::encode(
                is_string($publicKey) ? $publicKey : $publicKey->getBinaryString()
            );
            $passkey->attestation_format = $result->attestationFormat ?? 'none';
            $passkey->aaguid = $result->AAGUID ?? '';
            $passkey->counter = $result->signatureCounter ?? 0;
            $passkey->save();

            // Re-check the limit after saving to close the count/save race:
            // if concurrent registrations pushed us over the cap, roll back
            // this newest one.
            if (Passkey::where('uid', $user->uid)->count() > $maxPasskeys) {
                $passkey->delete();
                return json(trans('SysHub\Passkey::messages.error.max_passkeys_reached', ['max' => $maxPasskeys]), 1);
            }

            // Note: the created_at accessor already returns "Y-m-d H:i:s"
            // (a plain string), so do NOT call ->toDateTimeString() on it.
            return response()->json([
                'code' => 0,
                'message' => trans('SysHub\Passkey::messages.register.success'),
                'data' => [
                    'passkey' => [
                        'id' => $passkey->id,
                        'name' => $passkey->name,
                        'created_at' => (string) $passkey->created_at,
                    ],
                ],
            ]);
            
        } catch (\Throwable $e) {
            $message = trans('SysHub\Passkey::messages.error.registration_failed');
            if (config('app.debug')) {
                $message .= ': ' . get_class($e) . ': ' . $e->getMessage();
            }
            \Log::error('[Passkey] Registration failed', [
                'exception' => $e,
                'uid' => Auth::id(),
            ]);
            return json($message, 1);
        }
    }

    /**
     * Rename a passkey
     */
    public function rename(Request $request, Passkey $passkey)
    {
        // Authorization check
        if ((int) $passkey->uid !== (int) Auth::id()) {
            return json(trans('SysHub\Passkey::messages.error.unauthorized'), 1);
        }
        
        $name = trim($request->input('name', ''));
        if ($name === '') {
            return json(trans('SysHub\Passkey::messages.error.name_required'), 1);
        }
        
        // Validate name length (DB column is string(64))
        if (mb_strlen($name) > 64) {
            return json(trans('SysHub\Passkey::messages.error.name_too_long'), 1);
        }
        
        $passkey->name = $name;
        $passkey->save();
        
        return json(trans('SysHub\Passkey::messages.rename.success'), 0, [
            'passkey' => [
                'id' => $passkey->id,
                'name' => $passkey->name,
            ],
        ]);
    }

    /**
     * Delete a passkey
     */
    public function delete(Passkey $passkey)
    {
        // Authorization check
        if ((int) $passkey->uid !== (int) Auth::id()) {
            return json(trans('SysHub\Passkey::messages.error.unauthorized'), 1);
        }
        
        $passkey->delete();
        
        return json(trans('SysHub\Passkey::messages.delete.success'), 0);
    }
}
