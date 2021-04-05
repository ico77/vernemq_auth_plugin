-module(vernemq_auth_plugin_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    vernemq_auth_plugin_config:load(),
    vernemq_auth_plugin_store:new(),
    vernemq_auth_plugin_sup:start_link().

stop(_State) ->
    ok.
