-module(vernemq_auth_plugin_store).

-export([new/0, store/2, lookup/1, delete/1]).

-include_lib("jose/include/jose.hrl").

-define(CACHE, vmq_auth_plugin_cache).

-spec new() -> ok.
new() ->
    ets:new(?CACHE,
            [public, set, named_table, {read_concurrency, true}, {write_concurrency, true}]),
    ok.

-spec store(binary(), map()) -> ok | {error, atom()}.
store(ClientId, Token) ->
    case convert_jwt_to_tuple(Token) of
        {error, Reason} -> {error, Reason};
        {Expiry, Retain, TopicAuthorizations} ->
            ets:insert(?CACHE, {ClientId, Expiry, Retain, TopicAuthorizations}),
            ok
    end.

-spec lookup(binary()) -> [tuple()].
lookup(ClientId) ->
    ets:lookup(?CACHE, ClientId).

-spec delete(binary()) -> true.
delete(ClientId) ->
    ets:delete(?CACHE, ClientId).

convert_jwt_to_tuple(Token) ->
    Expiry = maps:get(<<"exp">>, Token, 0),
    Retain = maps:get(<<"retain">>, Token, false),
    Authorizations = maps:get(<<"authz">>, Token, []),
    case convert_topic_authorizations_to_tuple_list(Authorizations, []) of
        {error, Reason} -> {error, Reason};
        ConvertedAuthorizations -> {Expiry, Retain, ConvertedAuthorizations}
    end.

convert_topic_authorizations_to_tuple_list([], ConvertedAuthorizations) ->
    ConvertedAuthorizations;
convert_topic_authorizations_to_tuple_list([Authorization | Rest], ConvertedAuthorizations) ->
    case convert_single_authorization(Authorization) of
        {error, Reason} -> {error, Reason};
        ConvertedAuthorization -> convert_topic_authorizations_to_tuple_list(Rest, [ConvertedAuthorization | ConvertedAuthorizations])
    end.

convert_single_authorization(TopicAuth) ->
    case maps:find(<<"action">>, TopicAuth) of
        error -> {error, missing_action_claim};
        {ok, ActionClaim} -> 
            Action = erlang:binary_to_atom(ActionClaim, utf8),
            case maps:find(<<"topic">>, TopicAuth) of
                error -> {error, missing_topic_claim};
                {ok, Topic} -> {Action, Topic}
            end
    end.