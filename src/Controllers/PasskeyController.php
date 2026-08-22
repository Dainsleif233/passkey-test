<?php

namespace SysHub\Passkey\Controllers;

use App\Http\Controllers\Controller;
use Auth;
use SysHub\Passkey\Models\Passkey;
use SysHub\Passkey\Support\Base64Url;
use SysHub\Passkey\Support\ChallengeStore;
use SysHub\Passkey\Support\Requirements;
use SysHub\Passkey\Support\WebAuthnErrors;
use SysHub\Passkey\Support\WebAuthnFactory;
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
            return json('ok', 0, $passkeys->map(function ($pk) {
                return [
                    'id' => $pk->id,
                    'name' => $pk->name,
                    'created_at' => $pk->created_at,
                    'last_used_at' => $pk->last_used_at,
                ];
            })->all());
        }
        
        return view('SysHub\Passkey::manage', compact('passkeys'));
    }

    /**
     * Get creation options for new passkey
     */
    public function createOptions()
    {
        if ($failure = Requirements::failure()) {
            return $failure;
        }
        
        $user = Auth::user();
        $webauthn = WebAuthnFactory::make();

        // Get existing credential IDs to exclude
        $excludeIds = Passkey::where('uid', $user->uid)
            ->pluck('credential_id')
            ->map(function ($credentialId) {
                return Base64Url::decodeInput($credentialId);
            })
            ->filter()
            ->values()
            ->all();

        // lbuchs/WebAuthn v2.2 getCreateArgs signature:
        //   (userId, userName, userDisplayName, timeout,
        //    requireResidentKey, requireUserVerification,
        //    crossPlatformAttachment, excludeCredentialIds)
        // Resident keys are required for usernameless login. The args builders
        // accept the raw 'required'/'preferred'/'discouraged' string, which is
        // what we want here so that "discouraged" is not silently downgraded to
        // "preferred" (only the process* functions need a boolean).
        $userId = pack('J', $user->uid);
        $args = $webauthn->getCreateArgs(
            $userId,
            $user->email,
            $user->nickname,
            60,
            true, // requireResidentKey: discoverable credential
            WebAuthnFactory::getUserVerification(),
            null, // crossPlatformAttachment: allow platform and cross-platform
            $excludeIds
        );
        
        // Store challenge in session
        ChallengeStore::put('create', $webauthn->getChallenge()->getBinaryString());

        return response()->json($args);
    }

    /**
     * Register a new passkey
     */
    public function register(Request $request)
    {
        if ($failure = Requirements::failure()) {
            return $failure;
        }
        
        $user = Auth::user();
        
        // Check max passkeys limit
        $maxPasskeys = self::maxPasskeys();
        $currentCount = Passkey::where('uid', $user->uid)->count();
        
        if ($currentCount >= $maxPasskeys) {
            return json(trans('SysHub\Passkey::messages.error.max_passkeys_reached', ['max' => $maxPasskeys]), 1);
        }
        
        // Validate and decode base64url fields (decodeInput guards against a
        // JSON null/array reaching decode(string) and throwing a TypeError
        // outside the try block below).
        $clientDataJSON = Base64Url::decodeInput($request->input('clientDataJSON'));
        $attestationObject = Base64Url::decodeInput($request->input('attestationObject'));
        
        if ($clientDataJSON === null || $attestationObject === null) {
            return json(trans('SysHub\Passkey::messages.error.invalid_data'), 1);
        }

        // Validate the name BEFORE verifying the attestation: rejecting after
        // processCreate would leave the user's authenticator holding a
        // credential the server never stored, and the consumed challenge would
        // force a whole new ceremony.
        $name = trim((string) $request->input('name', ''));
        if ($name === '') {
            $name = 'Passkey ' . ($currentCount + 1);
        }

        // DB column is string(64)
        if (mb_strlen($name) > 64) {
            return json(trans('SysHub\Passkey::messages.error.name_too_long'), 1);
        }

        // Get and consume challenge
        $challenge = ChallengeStore::pop('create', $clientDataJSON);
        if ($challenge === null) {
            return json(trans('SysHub\Passkey::messages.error.invalid_challenge'), 1);
        }

        try {
            $webauthn = WebAuthnFactory::make();

            // Verify attestation. lbuchs/WebAuthn v2.2 processCreate signature:
            //   (clientDataJSON, attestationObject, challenge,
            //    requireUserVerification, requireUserPresent,
            //    failIfRootMismatch, requireCtsProfileMatch)
            // Note there is no residentKey check here: the spec gives the server
            // no reliable way to verify it from the attestation, so discoverable
            // credentials are only requested via createOptions.
            $result = $webauthn->processCreate(
                $clientDataJSON,
                $attestationObject,
                $challenge,
                WebAuthnFactory::requireUserVerification(),
                true,  // requireUserPresent
                false, // failIfRootMismatch = false
                false  // requireCtsProfileMatch = false
            );

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
            // AAGUID is the raw 16-byte binary from authenticatorData
            // (AuthenticatorData::_readAttestData). Writing it directly into a
            // utf8mb4 varchar column fails with MySQL error 1366 under strict
            // mode, so store the hex form (32 chars, fits varchar(36)).
            $aaguid = $result->AAGUID ?? '';
            if (!is_string($aaguid)) {
                $aaguid = method_exists($aaguid, 'getBinaryString') ? $aaguid->getBinaryString() : '';
            }
            $passkey->aaguid = $aaguid === '' ? '' : bin2hex($aaguid);
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
            return json(trans('SysHub\Passkey::messages.register.success'), 0, [
                'passkey' => [
                    'id' => $passkey->id,
                    'name' => $passkey->name,
                    'created_at' => (string) $passkey->created_at,
                ],
            ]);
            
        } catch (\Throwable $e) {
            $message = WebAuthnErrors::message($e, 'registration_failed');
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
     * Configured per-user passkey cap.
     *
     * The option is stored as free-form text; ConfigController normalizes it on
     * save, but values written before that (or by hand) still need a sane
     * fallback here instead of silently collapsing to 1.
     */
    private static function maxPasskeys(): int
    {
        $configured = filter_var(option('passkey_max_passkeys', 5), FILTER_VALIDATE_INT);

        return $configured === false ? 5 : min(50, max(1, $configured));
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
