<?php

namespace App\Http\Controllers;

use App\Mail\SendConfirmEmail;
use App\Models\Mobilizon;
use App\Models\User;
use DB;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Mail;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     */
    public function __construct() {}

    /**
     * Get a JWT via given credentials.
     *
     */
    public function login(): JsonResponse
    {
        $credentials = request(['email', 'password']);
        $token = auth()->attempt($credentials);

        if (!$token) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $mclient = Mobilizon::getInstance();
        if (!$mclient->user) {
            return response()->json(['error' => 'user_not_validated'], 404);
        }

        $user = auth()->user();
        if (!$user->is_active) {
            return response()->json(['error' => 'user_deactivated'], 403);
        }

        return response()->json([
            'access_token' => $token,
            'user' => $user,
            'person' => $mclient->person
        ]);
    }

    public function register(Request $request): JsonResponse
    {
        $valideInputs = $request->validate([
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if (!$valideInputs) {
            return response()->json(['error' => 'Validation failed'], 422);
        }
        if (User::where('email', $request->input('email'))->exists()) {
            return response()->json(['error' => 'Email already exists'], 409);
        }

        $mclient = Mobilizon::getInstance(true);
        $mobilizon_password = Str::random(32);
        $createdMobilizonUser = $mclient->createUser($request->input('email'), $mobilizon_password);

        if (isset($createdMobilizonUser['errors'])) {
            return response()->json(['error' => $createdMobilizonUser['errors'][0]['message']], 500);
        }

        $user = new User();
        $user->email = $request->input('email');
        $user->password = $request->input('password');
        $user->mobilizon_email = $request->input('email');
        $user->mobilizon_password = $mobilizon_password;
        $user->email_verification_token = Str::uuid()->toString();
        $user->mobilizon_user_id = $createdMobilizonUser['data']['createUser']['id'];
        $user->save();

        try {
            Mail::to($user->email)
                ->send(new SendConfirmEmail($user->email_verification_token));
        } catch (\Exception $e) {
            Log::error('Error sending confirmation email: ' . $e->getMessage());
        }

        $token = auth()->login($user);

        return response()->json([
            'access_token' => $token,
            'user' => $user
        ]);
    }

    public function forgotPassword(Request $request): JsonResponse
    {
        $validInputs = $request->validate([
            'email' => 'required|email',
        ]);

        if (!$validInputs) {
            return response()->json(['error' => 'Bitte geben Sie eine gültige E-Mail-Adresse ein'], 422);
        }

        if (!User::where('email', $request->input('email'))->exists()) {
            return response()->json(['message' => 'Wenn diese E-Mail-Adresse in unserem System vorhanden ist, erhalten Sie eine E-Mail mit einem Link zum Zurücksetzen Ihres Passworts.']);
        }

        $status = Password::sendResetLink(
            $request->only('email')
        );

        return $status === Password::RESET_LINK_SENT
            ? response()->json(['message' => 'Wenn diese E-Mail-Adresse in unserem System vorhanden ist, erhalten Sie eine E-Mail mit einem Link zum Zurücksetzen Ihres Passworts.'])
            : response()->json(['error' => 'Fehler beim Senden des Passwort-Zurücksetzen-Links'], 500);
    }

    public function validateUser(Request $request): JsonResponse
    {
        $verificationToken = $request->input('verificationToken');

        $user = User::where('email_verification_token', $verificationToken)->first();
        if (!$user) {
            return response()->json(['error' => 'User validation failed'], 500);
        }
        $systemAdmin = User::find(1);

        $mclient = Mobilizon::getInstance(false, $systemAdmin);

        $mresponse = $mclient->adminUpdateUser([
            'id' => $user->mobilizon_user_id,
            'confirmed' => true
        ]);

        if ($mclient->hasError($mresponse)) {
            return response()->json(['error' => 'User validation failed'], 500);
        }

        $user->email_verified_at = now();
        $user->email_verification_token = null;
        $user->is_active = true;
        $user->save();

        return response()->json(['message' => 'User validated successfully']);
    }

    public function resetPassword(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'token' => 'required',
            'password' => 'required|string|min:6|confirmed',
            'password_confirmation' => 'required|string|min:6|same:password'
        ]);

        if (!$validated) {
            return response()->json(['error' => 'Fehlende oder ungültige Eingaben'], 422);
        }

        $plainToken = $validated['token'];
        $record = DB::table('password_reset_tokens')
            ->get()
            ->first(function ($row) use ($validated, $plainToken) {
                return isset($row->token) && Hash::check($plainToken, $row->token);
            });

        if (!$record) {
            return response()->json(['error' => 'Ungültiges oder abgelaufenes Token'], 400);
        }

        $status = Password::reset(
            [
                'email' => $record->email,
                ...$request->only('password', 'token')
            ],
            function ($user, $password) {
                $user->forceFill([
                    'password' => Hash::make($password)
                ])->setRememberToken(Str::random(60));
                $user->setRememberToken(Str::random(60));
                $user->save();

                event(new PasswordReset($user));
            }
        );

        return $status === Password::PASSWORD_RESET
            ? response()->json(['message' => 'Passwort erfolgreich zurückgesetzt'])
            : response()->json([
                    'error' =>  'Fehler beim Zurücksetzen des Passworts',
                    'status' => $status,
                    'rp_record_email' => $record->email,
                    'rp_record_token' => $record->token
                ], 500);
    }

    /**
     * Get the authenticated User.
     *
     */
    public function me(): JsonResponse
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     */
    public function logout(): JsonResponse
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     */
    public function refresh(): JsonResponse
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     */
    protected function respondWithToken(string $token): JsonResponse
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}
