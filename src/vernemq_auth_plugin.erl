-module(vernemq_auth_plugin).

-behaviour(auth_on_register_hook).
-behaviour(auth_on_subscribe_hook).
-behaviour(auth_on_publish_hook).
-behaviour(on_client_gone_hook).
-behaviour(on_client_offline_hook).

-export([auth_on_register/5,
         auth_on_publish/6,
         auth_on_subscribe/3,
		 on_client_gone/1,
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

auth_on_register({_IpAddr, _Port} = Peer, {_MountPoint, _ClientId} = SubscriberId, UserName, Password, CleanSession) ->
    {ok, SigningKey} = 	application:get_env(vernemq_auth_plugin, signing_key),
	JWK = #{
	  <<"kty">> => <<"oct">>,
	  <<"k">> => jose_base64url:encode(SigningKey)
	},
    case jose_jwt:verify(JWK, Password) of
		{true, Token, Signature} ->
			check_credentials(UserName, _ClientId, Token, fun vernemq_auth_plugin_store:store/2);
		{false, ErrorToken, ErrorSignature} ->
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
auth_on_publish(UserName, {_MountPoint, _ClientId} = SubscriberId, QoS, Topic, Payload, IsRetain) ->
    case vernemq_auth_plugin_store:lookup(_ClientId) of
		[] -> 
			error_logger:info_msg("Token not found for client: ~p", [_ClientId]),
			{error, token_not_found};
		[{Key, Token}] ->
			authorize_publish(_ClientId, Topic, IsRetain, Token)	
    end.

%% do whatever you like with the params, all that matters
%% is the return value of this function
%%
%% 1. return 'ok' -> SUBSCRIBE is authorized
%% 2. return 'next' -> leave it to other plugins to decide
%% 3. return {error, whatever} -> auth chain is stopped, and no SUBACK is sent

%% we return 'ok'
auth_on_subscribe(UserName, {_MountPoint, _ClientId} = SubscriberId, [{_Topic, _QoS}|_] = Topics) ->
    case vernemq_auth_plugin_store:lookup(_ClientId) of
		[] -> 
			error_logger:info_msg("Token not found for client: ~p", [_ClientId]),
			{error, token_not_found};
		[{Key, Token}] ->
			authorize_subscribe(_ClientId, Topics, Token)	
    end.

on_client_gone({_MountPoint, _ClientId} = SubscriberId) ->
    vernemq_auth_plugin_store:delete(_ClientId),
	ok.

on_client_offline({_MountPoint, _ClientId} = SubscriberId) ->
    vernemq_auth_plugin_store:delete(_ClientId),
	ok.

check_credentials(UserName, ClientId, Token = #jose_jwt{fields=Fields}, StoreFun) ->
	case {ClientId, maps:find(<<"client-id">>, Fields)} of
		{V, {ok, V}} ->
			apply(StoreFun, [ClientId, Fields]),
			ok;
		{_, _} ->
			error_logger:info_msg("Supplied client id does not match client id from token, supplied: ~p", [ClientId]),
			{error, client_id_mismatch}
	end.

authorize_publish(ClientId, Topic, IsRetain, Token) ->
	case check_token_expiry(ClientId, Token) of
		{error, Reason} ->
			{error, Reason};
		ok ->
			authorize_publish_topic(Topic, IsRetain, Token)
	end.

authorize_subscribe(ClientId, Topics, Token) ->
	case check_token_expiry(ClientId, Token) of
		{error, Reason} ->
			{error, Reason};
		ok ->
			vernemq_auth_plugin_subscribe:authorize(ClientId, Topics, Token)
	end.

check_token_expiry(ClientId, Token) ->
	ExpiryTimeStamp = maps:get(<<"exp">>, Token),
	TimeStamp = erlang:system_time(seconds),
	case ExpiryTimeStamp < TimeStamp of
		true ->
			vernemq_auth_plugin_store:delete(ClientId),
			{error, token_expired};
		false ->
			ok
	end.

authorize_publish_topic(Topic, IsRetain, Token) ->
	ClaimsRetain = maps:get(<<"retain">>, Token, false),	
	case maps:find(<<"topic-claims">>, Token) of 
		{ok, Claims} ->
			check_publish_claims(Topic, IsRetain, Claims, ClaimsRetain);
		_ ->
			{error, claims_missing}
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
	
check_publish_claim(Topic, IsRetain, Claim, ClaimsRetain) ->
	IsRetainAllowed = IsRetain =:= false orelse IsRetain =:= ClaimsRetain,
	IsActionAllowed = case maps:find(<<"action">>, Claim) of 
						{ok, <<"publish">>} ->
							true;
						_ ->
							false
					  end,
	IsTopicAllowed = case maps:find(<<"topic">>, Claim) of
						{ok, ClaimTopic} ->
							SplittedTopic = vernemq_auth_plugin_topic:word(ClaimTopic),
							vernemq_auth_plugin_topic:match(Topic, SplittedTopic);
						_ ->
							false
					 end,
	IsRetainAllowed andalso IsActionAllowed andalso IsTopicAllowed.
