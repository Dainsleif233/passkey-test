<?php

namespace SysHub\Passkey\Models;

use Illuminate\Database\Eloquent\Model;

class Passkey extends Model
{
    protected $table = 'passkeys';
    protected $primaryKey = 'id';
    public $timestamps = true;

    protected $fillable = [
        'uid',
        'name',
        'credential_id',
        'credential_id_hash',
        'public_key',
        'attestation_format',
        'aaguid',
        'counter',
        'last_used_at',
    ];

    protected $hidden = [
        'public_key',
    ];

    /**
     * Get the user that owns the passkey
     * Note: Blessing Skin uses 'uid' as the primary key for users
     */
    public function user()
    {
        return $this->belongsTo('App\Models\User', 'uid', 'uid');
    }
}