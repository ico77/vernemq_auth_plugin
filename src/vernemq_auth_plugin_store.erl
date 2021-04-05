-module(vernemq_auth_plugin_store).

-export([new/0, store/2, lookup/1, delete/1]).

-include_lib("jose/include/jose.hrl").

-type jose_jwt() :: #jose_jwt{}.

-define(CACHE, vmq_auth_plugin_cache).

-spec new() -> ok.
new() ->
    ets:new(?CACHE,
            [public, set, named_table, {read_concurrency, true}, {write_concurrency, true}]),
    ok.

-spec store(binary(), map()) -> true.
store(ClientId, Token) ->
    ets:insert(?CACHE, {ClientId, Token}).

-spec lookup(binary()) -> [tuple()].
lookup(ClientId) ->
    ets:lookup(?CACHE, ClientId).

-spec delete(binary()) -> true.
delete(ClientId) ->
    ets:delete(?CACHE, ClientId).
