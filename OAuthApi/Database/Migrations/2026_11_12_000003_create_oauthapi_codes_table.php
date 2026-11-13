<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateOauthapiCodesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        // Authorization codes: single use, short lived.
        Schema::create('oauthapi_codes', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('authorization_id')->index();
            $table->string('code_hash', 64)->unique();
            $table->text('scopes');

            // Only set when the authorize request named a redirect URI; the
            // token request must then repeat it.
            $table->text('redirect_uri')->nullable();

            $table->string('code_challenge', 128)->nullable();
            $table->string('code_challenge_method', 10)->nullable();

            $table->timestamp('expires_at')->nullable();
            $table->timestamp('used_at')->nullable();
            $table->timestamp('created_at')->nullable();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('oauthapi_codes');
    }
}
