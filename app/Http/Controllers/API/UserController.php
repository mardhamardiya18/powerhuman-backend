<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

use Laravel\Fortify\Rules\Password as RulesPassword;

class UserController extends Controller
{
    public function login(Request $request)
    {
        try {

            // Validate Request
            $request->validate([
                'email' => 'required|email',
                'password' => 'required'
            ]);

            // Find User by Email
            $credentials = request(['email', 'password']);
            if (!Auth::attempt($credentials)) {
                return ResponseFormatter::error('Unauthorize', 401);
            }

            $user = User::where('email', $request->email)->first();
            if (!Hash::check($request->password, $user->password)) {
                throw new Exception("Invalid Passowrd");
            }

            // Generate Token
            $token = $user->createToken('token')->plainTextToken;
            return ResponseFormatter::success([
                'access_token' => $token,
                'token_type'   => 'Bearer',
                'user'  => $user
            ], 'Login Success');
        } catch (Exception $e) {

            return ResponseFormatter::error($e->getMessage());
        }
    }

    public function register(Request $request)
    {
        try {
            // Validate Request
            $request->validate([
                'name' => 'required|string|max:255',
                'email' => 'required|email|unique:users',
                'password'  => new RulesPassword,
            ]);

            // Create User
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password'  => Hash::make($request->password)
            ]);

            // Generate token
            $token = $user->createToken('token')->plainTextToken;

            return ResponseFormatter::success([
                'access_token'  => $token,
                'token_type'    => 'Bearer',
                'user'  => $user,
            ], 'Register Success');
        } catch (Exception $e) {
            return ResponseFormatter::error($e->getMessage());
        }
    }
}
