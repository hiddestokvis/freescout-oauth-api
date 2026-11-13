<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateOauthapiTokensTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        // One row per access token / refresh token pair. Only HMACs of the
        // tokens are stored.
        Schema::create('oauthapi_tokens', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('authorization_id')->index();
            $table->integer('auth_code_id')->nullable()->index();
            $table->string('access_hash', 64)->unique();
            $table->string('refresh_hash', 64)->nullable()->unique();
            $table->text('scopes');

            $table->timestamp('access_expires_at')->nullable();
            $table->timestamp('refresh_expires_at')->nullable();

            // Set when the refresh token has been exchanged for a new pair.
            // A rotated refresh token that shows up again means it leaked,
            // and every token of the authorization is revoked.
            $table->timestamp('rotated_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('oauthapi_tokens');
    }
}
