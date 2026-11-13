<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateOauthapiClientsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        // Applications registered by an administrator.
        Schema::create('oauthapi_clients', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name', 100);
            $table->string('client_id', 64)->unique();

            // Only an HMAC of the secret is stored; it is shown once, on
            // creation. Public clients (SPAs, desktop and CLI apps) have no
            // secret and must use PKCE.
            $table->string('secret_hash', 64)->nullable();
            $table->boolean('confidential')->default(true);

            $table->text('redirect_uris');  // JSON list, matched exactly
            $table->text('scopes');         // JSON list of scopes the app may ask for
            $table->boolean('active')->default(true);

            $table->integer('created_by')->nullable();
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
        Schema::dropIfExists('oauthapi_clients');
    }
}
