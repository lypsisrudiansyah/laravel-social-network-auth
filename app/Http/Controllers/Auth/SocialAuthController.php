<?php

namespace App\Http\Controllers\Auth;

use App\User;
use Exception;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;

class SocialAuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('guest');
    }

    protected $providers = [
        'github',
        'facebook'
    ];

    public function show()
    {
        return view('auth.social');
    }

    public function redirectToProvider($driver)
    {
        if (! $this->isProviderAllowed($driver)) {
            return $this->sendFailedResponse("{$driver} is not currently supported");
        }

        try {
            return Socialite::driver($driver)->redirect();
        } catch (Exception $e) {
            // You should show something simple fail message
            return $this->sendFailedResponse($e->getMessage());
        }
    }

    public function handleProviderCallback($driver)
    {
        try {
            $user = Socialite::driver($driver)->user();
        } catch(Exception $e) {
            return $this->sendFailedResponse($e->getMessage());
        }
        
        if ($driver == "facebook") {
            $user->email = $user->id;
        }

        Log::info("fb", [$user]);
        // check for email in returned user
        return empty($user->email)
        ? $this->sendFailedResponse("No email id returned from {$driver} provider.")
        : $this->loginOrCreateAccount($user, $driver);
    }

    public function sendSuccessResponse()
    {
        return redirect()->intended('home');
    }

    public function sendFailedResponse($msg = null)
    {
        return redirect()->route('social.login')
            ->withErrors(["msg" => $msg ?: "Unable to login, try with another provider to login :) "]);
    }

    public function loginOrCreateAccount($providerUser, $driver)
    {
        // check for already has account
        $user = User::where('email', $providerUser->getEmail())->first();

        if ($driver == 'facebook') {
            $user = User::where('email', $providerUser->getId())->first();
            $providerUser->email = $providerUser->id;
        } else {
            $user = User::where('email', $providerUser->getEmail())->first();
        }

        // if already found
        if ($user) {
            // update the avatar and provider that might have changed
            $user->update([
                'avatar' => $providerUser->avatar,
                'provider' => $driver,
                'provider_id' => $providerUser->id,
                'access_token' => $providerUser->token
            ]);
        } else {
            // create new user
            $user = User::create([
                'name' => $providerUser->name,
                'email' => $providerUser->email,
                'avatar' => $providerUser->avatar,
                'provider' => $driver,
                'provider_id' => $providerUser->getId(),
                'access_token' => $providerUser->token,
                // user can reset password to create a password
                'password' => ''
            ]);
        }

        // Login
        Auth::login($user, true);

        return $this->sendSuccessResponse();
    }

    // check for provider allowed and services configured
    public function isProviderAllowed($driver)
    {
        return in_array($driver, $this->providers) && config()->has("services.{$driver}");
    }
}
