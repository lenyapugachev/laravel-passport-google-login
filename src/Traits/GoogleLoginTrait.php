<?php

namespace LenyaPugachev\PassportGoogleLogin\Traits;

use Illuminate\Http\Request;
use League\OAuth2\Server\Exception\OAuthServerException;

trait GoogleLoginTrait {
	/**
	 * Logs a App\User in using a Google token via Passport
	 *
	 * @param \Illuminate\Http\Request $request
	 *
	 * @return \Illuminate\Database\Eloquent\Model|null
	 * @throws \League\OAuth2\Server\Exception\OAuthServerException
	 */
	public function loginGoogle( Request $request ) {
		try {
			/**
			 * Check if the 'goole_token' as passed.
			 */
			if ( $request->get( 'google_token' ) ) {

				$ch = curl_init();
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

				if ( $request->get( 'android' ) ) {
					curl_setopt($ch, CURLOPT_URL, "https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=" . $request->get( 'google_token' ));
				} else {
					curl_setopt($ch, CURLOPT_URL, "https://www.googleapis.com/userinfo/v2/me");
					curl_setopt($ch, CURLOPT_HTTPHEADER, array(
					    'Authorization: Bearer ' . $request->get( 'google_token' )
					));
				}

				$googleUser = json_decode(curl_exec($ch));
				curl_close($ch);

				if ( $request->get( 'android' ) ) {
					$googleUser->id = $googleUser->sub;
				}

				/**
				 * Check if the user has already signed up.
				 */
				$userModel = config( 'auth.providers.users.model' );

				/**
				 * Create a new user if they haven't already signed up.
				 */
				$google_id_column  = config( 'google-passport.registration.google_id', 'google_id' );
				$name_column       = config( 'google-passport.registration.name', 'name' );
				$first_name_column = config( 'google-passport.registration.first_name', 'first_name' );
				$last_name_column  = config( 'google-passport.registration.last_name', 'last_name' );
				$email_column      = config( 'google-passport.registration.email', 'email' );
				$password_column   = config( 'google-passport.registration.password', 'password' );

				$user = $userModel::where($google_id_column, $googleUser->id)->first();

				if (!$user) {
				    $user = $userModel::where($email_column, $googleUser->email)->first();
					
				    if($user) {
						$user->{$google_id_column} = $googleUser->id;
				    	$user->save();
				    }
				}

				if (!$user) {
					$user = new $userModel();
					$user->{$google_id_column} = $googleUser->id;

					if ($first_name_column) {
						$user->{$first_name_column} = $googleUser->given_name;
					}
					if ($last_name_column) {
						$user->{$last_name_column} = $googleUser->family_name;
					}
					if ($name_column) {
						$user->{$name_column} = $googleUser->name;
					}

					$user->{$email_column} = $googleUser->email;
					$user->{$password_column} = bcrypt( uniqid( 'plus_', true ) ); // Random password.
					$user->save();
				}

				return $user;
			}
		} catch ( \Exception $e ) {
// 			die( $e->getMessage() );
			throw OAuthServerException::accessDenied( $e->getMessage() );
		}

		return null;
	}
}
