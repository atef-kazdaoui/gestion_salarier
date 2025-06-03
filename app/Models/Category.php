<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use App\Models\Document;

class Category extends Model
{
    use HasFactory;

    protected $fillable = ['nom'];

    public function documents()
    {
        return $this->hasMany(Document::class);
    }
}
