<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateOauthapiWebhooksTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        // Webhooks created through OAuth. The webhook itself is a normal
        // row in the API & Webhooks module's `webhooks` table; this row
        // records whose access it is limited to.
        Schema::create('oauthapi_webhooks', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('webhook_id')->unique();
            $table->integer('authorization_id')->index();
            $table->integer('user_id')->index();
            $table->text('mailbox_ids')->nullable();  // JSON list; null = every mailbox the user can see
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
        Schema::dropIfExists('oauthapi_webhooks');
    }
}
