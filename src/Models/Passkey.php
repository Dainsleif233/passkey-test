<?php

namespace SysHub\Passkey\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Casts\Attribute;

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

    /**
     * Get the created_at as a formatted string
     */
    protected function createdAt(): Attribute
    {
        return Attribute::make(
            get: fn ($value) => $value ? \Carbon\Carbon::parse($value)->toDateTimeString() : null,
        );
    }

    /**
     * Get the last_used_at as a formatted string
     */
    protected function lastUsedAt(): Attribute
    {
        return Attribute::make(
            get: fn ($value) => $value ? \Carbon\Carbon::parse($value)->toDateTimeString() : null,
        );
    }
}
