<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Auth\Events\Registered;
use App\Models\User;

class AuthController extends Controller
{
    // INSCRIPTION
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|unique:users,email',
            'password' => [
                'required',
                'string',
                'min:8',
                'confirmed',
                'regex:/[a-z]/',      // minuscule
                'regex:/[A-Z]/',      // majuscule
                'regex:/[0-9]/',      // chiffre
                'regex:/[@$!%*#?&]/', // caractère spécial
            ],
        ], [
            'password.regex' => 'Le mot de passe doit contenir une majuscule, une minuscule, un chiffre et un caractère spécial.',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'validation_error',
                'errors' => $validator->errors()
            ], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        event(new Registered($user)); // envoie l’email de vérification

        return response()->json([
            'status' => 'success',
            'message' => 'Utilisateur inscrit avec succès. Veuillez vérifier votre adresse email.',
            'user' => $user
        ], 201);
    }

    // CONNEXION
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'validation_error',
                'errors' => $validator->errors()
            ], 422);
        }

        $credentials = $request->only('email', 'password');

        if (!Auth::attempt($credentials)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Email ou mot de passe incorrect.'
            ], 401);
        }

        $user = Auth::user();

        if (!$user->hasVerifiedEmail()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Veuillez vérifier votre adresse email avant de vous connecter.'
            ], 403);
        }

        return response()->json([
            'status' => 'success',
            'message' => 'Connexion réussie',
            'user' => $user
        ], 200);
    }
}
