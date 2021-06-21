-module(vernemq_auth_plugin).

-behaviour(auth_on_register_hook).
-behaviour(auth_on_subscribe_hook).
-behaviour(auth_on_publish_hook).
-behaviour(on_client_gone_hook).
-behaviour(on_client_offline_hook).

-export([auth_on_register/5, auth_on_publish/6, auth_on_subscribe/3, on_client_gone/1,
         on_client_offline/1]).

-include_lib("jose/include/jose.hrl").

%%
%% IMPORTANT:
%%  these hook functions run in the session context
%%

%% do whatever you like with the params, all that matters
%% is the return value of this function
%%
%% 1. return 'ok' -> CONNECT is authenticated
%% 2. return 'next' -> leave it to other plugins to decide
%% 3. return {ok, [{ModifierKey, NewVal}...]} -> CONNECT is authenticated, but we might want to set some options used throughout the client session:
%%      - {mountpoint, NewMountPoint::string}
%%      - {clean_session, NewCleanSession::boolean}
%% 4. return {error, invalid_credentials} -> CONNACK_CREDENTIALS is sent
%% 5. return {error, whatever} -> CONNACK_AUTH is sent

%% we return 'ok'
auth_on_register(_, _, undefined, _, _) ->
    error_logger:info_msg("Username is not supplied"),
    {error, invalid_credentials};
auth_on_register(_, _, _, undefined, _) ->
    error_logger:info_msg("Password is not supplied"),
    {error, invalid_credentials};
auth_on_register({_IpAddr, _Port} = _Peer,
                 {_MountPoint, _ClientId} = _SubscriberId,
                 UserName,
                 Password,
                 _CleanSession) ->
    {ok, SigningKey} = application:get_env(vernemq_auth_plugin, signing_key),
    JWK = #{<<"kty">> => <<"oct">>, <<"k">> => jose_base64url:encode(SigningKey)},
    case jose_jwt:verify(JWK, Password) of
        {true, Token, _Signature} ->
            check_credentials(UserName, _ClientId, Token, fun vernemq_auth_plugin_store:store/2);
        {false, ErrorToken, _ErrorSignature} ->
            error_logger:info_msg("Error while verifying token: ~p", [ErrorToken]),
            {error, token_verification_failed}
    end.

%% do whatever you like with the params, all that matters
%% is the return value of this function
%%
%% 1. return 'ok' -> PUBLISH is authorized
%% 2. return 'next' -> leave it to other plugins to decide
%% 3. return {ok, NewPayload::binary} -> PUBLISH is authorized, but we changed the payload
%% 4. return {ok, [{ModifierKey, NewVal}...]} -> PUBLISH is authorized, but we might have changed different Publish Options:
%%     - {topic, NewTopic::string}
%%     - {payload, NewPayload::binary}
%%     - {qos, NewQoS::0..2}
%%     - {retain, NewRetainFlag::boolean}
%% 5. return {error, whatever} -> auth chain is stopped, and message is silently dropped (unless it is a Last Will message)
%%
%% we return 'ok'
auth_on_publish(_UserName,
                {_MountPoint, _ClientId} = _SubscriberId,
                _QoS,
                Topic,
                _Payload,
                IsRetain) ->
    case vernemq_auth_plugin_store:lookup(_ClientId) of
        [] ->
            error_logger:info_msg("Token not found for client: ~p", [_ClientId]),
            {error, token_not_found};
        [Token] ->
            authorize_publish(_ClientId, Topic, IsRetain, Token)
    end.

%% do whatever you like with the params, all that matters
%% is the return value of this function
%%
%% 1. return 'ok' -> SUBSCRIBE is authorized
%% 2. return 'next' -> leave it to other plugins to decide
%% 3. return {error, whatever} -> auth chain is stopped, and no SUBACK is sent

%% we return 'ok'
auth_on_subscribe(_UserName,
                  {_MountPoint, _ClientId} = _SubscriberId,
                  [{_Topic, _QoS} | _] = Topics) ->
    case vernemq_auth_plugin_store:lookup(_ClientId) of
        [] ->
            error_logger:info_msg("Token not found for client: ~p", [_ClientId]),
            {error, token_not_found};
        [Token] ->
            authorize_subscribe(_ClientId, Topics, Token)
    end.

on_client_gone({_MountPoint, _ClientId} = _SubscriberId) ->
    vernemq_auth_plugin_store:delete(_ClientId),
    ok.

on_client_offline({_MountPoint, _ClientId} = _SubscriberId) ->
    vernemq_auth_plugin_store:delete(_ClientId),
    ok.

check_credentials(_UserName, ClientId, _Token = #jose_jwt{fields = Fields}, StoreFun) ->
    case {ClientId, maps:find(<<"client-id">>, Fields)} of
        {V, {ok, V}} ->
            apply(StoreFun, [ClientId, Fields]);
        {_, _} ->
            error_logger:info_msg("Supplied client id does not match client id from token, supplied: ~p",
                                  [ClientId]),
            {error, client_id_mismatch}
    end.

authorize_publish(ClientId, Topic, IsRetain, {_, Expiry, ClaimsRetain, ClaimsTopics}) ->
    case check_token_expiry(ClientId, Expiry) of
        {error, Reason} ->
            {error, Reason};
        ok ->
            check_publish_claims(Topic, IsRetain, ClaimsTopics, ClaimsRetain)
    end.

authorize_subscribe(ClientId, Topics, {_, Expiry, _, ClaimsTopics}) ->
    case check_token_expiry(ClientId, Expiry) of
        {error, Reason} ->
            {error, Reason};
        ok ->
            vernemq_auth_plugin_subscribe:authorize_topics(Topics, ClaimsTopics)
    end.

check_token_expiry(ClientId, ExpiryTimeStamp) ->
    TimeStamp = erlang:system_time(seconds),
    case ExpiryTimeStamp < TimeStamp of
        true ->
            vernemq_auth_plugin_store:delete(ClientId),
            {error, token_expired};
        false ->
            ok
    end.

check_publish_claims(_, _, [], _) ->
    {error, publish_not_allowed};
check_publish_claims(Topic, IsRetain, [Claim | Rest], ClaimsRetain) ->
    case check_publish_claim(Topic, IsRetain, Claim, ClaimsRetain) of
        true ->
            ok;
        false ->
            check_publish_claims(Topic, IsRetain, Rest, ClaimsRetain)
    end.

check_publish_claim(Topic, IsRetain, {ClaimAction, ClaimTopic}, ClaimsRetain) ->
    IsRetainAllowed = IsRetain =:= false orelse IsRetain =:= ClaimsRetain,
    IsActionAllowed = ClaimAction =:= publish,
    
    SplittedTopic = vernemq_auth_plugin_topic:word(ClaimTopic),
    IsTopicAllowed = vernemq_auth_plugin_topic:match(Topic, SplittedTopic),

    IsRetainAllowed andalso IsActionAllowed andalso IsTopicAllowed.
