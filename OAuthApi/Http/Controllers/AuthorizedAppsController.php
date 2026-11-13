<?php

namespace Modules\OAuthApi\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Modules\OAuthApi\Entities\Authorization;

/**
 * "Authorized Apps" on a user's profile: the applications the user has
 * connected, with a button to cut each one off. Visible to the user and
 * to administrators.
 */
class AuthorizedAppsController extends Controller
{
    public function index($id)
    {
        $user = $this->profileUser($id);

        $authorizations = \Schema::hasTable('oauthapi_authorizations')
            ? Authorization::where('user_id', $user->id)
                ->whereNull('revoked_at')
                ->with('client')
                ->orderBy('created_at', 'desc')
                ->get()
                ->filter(function ($authorization) {
                    return (bool) $authorization->client;
                })
            : collect();

        return view('oauthapi::user_apps', [
            'user'           => $user,
            'authorizations' => $authorizations,
        ]);
    }

    public function revoke(Request $request, $id)
    {
        $user = $this->profileUser($id);

        $authorization = Authorization::where('user_id', $user->id)
            ->where('id', (int) $request->input('authorization_id'))
            ->first();

        if ($authorization) {
            $authorization->revoke();
            \Session::flash('flash_success_floating', __('Access revoked'));
        }

        return redirect()->route('oauthapi.user_apps', ['id' => $user->id]);
    }

    protected function profileUser($id)
    {
        $user = User::findOrFail($id);
        $auth_user = auth()->user();

        if (!$auth_user->isAdmin() && $auth_user->id != $user->id) {
            abort(403);
        }

        return $user;
    }
}
