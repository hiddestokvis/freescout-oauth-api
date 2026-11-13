@extends('layouts.app')

@section('title', __('Cannot connect application'))

@section('content')
<div class="container">
    <div class="row">
        <div class="col-md-8 col-md-offset-2">
            <div class="panel panel-default panel-shaded margin-top">
                <div class="panel-body">
                    <h3 class="margin-top-0">{{ __('Cannot connect application') }}</h3>
                    <p>{{ $message }}</p>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
