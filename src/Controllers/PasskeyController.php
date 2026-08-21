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
     * Show passkey management page
     */
    public function index()
    {
        $user = Auth::user();
        $passkeys = Passkey::where('uid', $user->uid)
            ->orderBy('created_at', 'desc')
            ->get();
        
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
        $uv = WebAuthnFactory::getUserVerification();
        
        // Get existing credential IDs to exclude
        $excludeIds = Passkey::where('uid', $user->uid)
            ->pluck('credential_id')
            ->map(function ($credentialId) {
                return Base64Url::decode($credentialId);
            })
            ->filter()
            ->values()
            ->all();
        
        // Get creation options
        $userId = pack('J', $user->uid);
        $args = $webauthn->getCreateArgs(
            $userId,
            $user->email,
            $user->nickname,
            60,
            'preferred',
            $uv,
            null,
            $excludeIds
        );
        
        // Store challenge in session
        ChallengeStore::put('create', $webauthn->getChallenge());
        
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
            return json(trans('SysHub\Passkey::messages.error.invalid_challenge'), 1);
        }
        
        try {
            $webauthn = WebAuthnFactory::make();
            $uv = WebAuthnFactory::getUserVerification();
            
            // Verify attestation
            $result = $webauthn->processCreate(
                $clientDataJSON,
                $attestationObject,
                $challenge,
                $uv,
                true,
                false, // failIfRootMismatch = false
                false  // requireCtsProfileMatch = false
            );
            
            // Get and validate passkey name
            $name = $request->input('name', '');
            if (empty($name)) {
                $name = 'Passkey ' . ($currentCount + 1);
            }
            
            // Validate name length (DB column is string(64))
            if (mb_strlen($name) > 64) {
                return json(trans('SysHub\Passkey::messages.error.name_too_long'), 1);
            }
            
            // Store passkey
            $passkey = new Passkey();
            $passkey->uid = $user->uid;
            $passkey->name = $name;
            $passkey->credential_id = Base64Url::encode($result['credentialId']->getBinaryString());
            $passkey->credential_id_hash = hash('sha256', $result['credentialId']->getBinaryString());
            $passkey->public_key = $result['credentialPublicKey'];
            $passkey->attestation_format = $result['attestationFormat'] ?? 'none';
            $passkey->aaguid = $result['AAGUID'] ?? '';
            $passkey->counter = $result['signatureCounter'] ?? 0;
            $passkey->save();
            
            return json(trans('SysHub\Passkey::messages.register.success'), 0, [
                'passkey' => [
                    'id' => $passkey->id,
                    'name' => $passkey->name,
                    'created_at' => $passkey->created_at->toDateTimeString(),
                ],
            ]);
            
        } catch (\Exception $e) {
            $message = trans('SysHub\Passkey::messages.error.registration_failed');
            if (config('app.debug')) {
                $message .= ': ' . $e->getMessage();
            }
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
        
        $name = $request->input('name', '');
        if (empty($name)) {
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