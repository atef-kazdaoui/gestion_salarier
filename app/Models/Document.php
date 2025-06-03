<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use App\Models\Category;

class Document extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'nom',
        'type',
        'chemin_fichier',
    ];

    // Relation : un document appartient à un utilisateur
    public function user()
    {
        return $this->belongsTo(User::class);
    }
    public function category()
{
    return $this->belongsTo(Category::class);
}

}
