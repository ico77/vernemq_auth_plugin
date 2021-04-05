-module(vernemq_auth_plugin_store).
-behaviour(gen_server).

-export([start_link/0]).

-export([store/2,
		 lookup/1,
		 delete/1]).

-export([init/1,
	     handle_call/3,
	     handle_cast/2,
	     handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {}).

-include_lib("stdlib/include/ms_transform.hrl").

-define(CACHE, vmq_auth_plugin_cache).
-define(EXPIRY, vmq_auth_plugin_expiry).

-define(DEFAULT_EXPIRY, 86400).

start_link() ->
    case lists:member(?CACHE, ets:all()) of
        true ->
            ignore;
        false ->
    		ets:new(?CACHE, [public, set, named_table,
                            {read_concurrency, true}]),
    	 	ets:new(?EXPIRY, [public, ordered_set, named_table,
                             {read_concurrency, true}])
    end,
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).
    
-spec store(binary(), map()) -> true.
store(ClientId, Token) ->
    case convert_jwt_to_tuple(Token) of
        {error, Reason} -> {error, Reason};
        {Expiry, Retain, TopicAuthorizations} ->
            ExpiryTimestamp = determine_expiry_timestamp(Expiry),
            ExpiryBucket = determine_expiry_bucket(ExpiryTimestamp),
            gen_server:call(?MODULE, {store, ClientId, Retain, TopicAuthorizations, ExpiryTimestamp, ExpiryBucket})
    end.

-spec lookup(binary()) -> [tuple()].
lookup(ClientId) ->
    ets:lookup(?CACHE, ClientId).

-spec delete(binary()) -> true.
delete(_ClientId) ->
    gen_server:call(?MODULE, {delete}).

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
	
%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    {ok, #state{}}.

handle_call({store, ClientId, Retain, TopicAuthorizations, ExpiryTimestamp, ExpiryBucket}, _From, _State) ->
	ets:insert(?CACHE, {ClientId, ExpiryTimestamp, Retain, TopicAuthorizations}),
	ets:insert(?EXPIRY, {{ExpiryBucket, ClientId}, true}),
    {reply, ok, _State};
handle_call({delete}, _From, _State) ->
	Timestamp = erlang:system_time(seconds),
	MS = ets:fun2ms(fun({{E, C}, _V}) when E < Timestamp -> {E, C} end),
	Expiries = ets:select(?EXPIRY, MS),
	lists:foreach(fun({ExpiryBucket, ClientId}) ->
		ets:match_delete(?EXPIRY, {{ExpiryBucket, ClientId}, '_'}),
		ets:select_delete(?CACHE, ets:fun2ms(fun({C, E, _, _}) when C =:= ClientId, E =< ExpiryBucket -> true end))
	end, Expiries),
    {reply, {ok}, _State}.
    
handle_cast(_Req, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
        {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
determine_expiry_timestamp(TokenExpiryTimestamp) ->
	DefaultExpiryTimestamp = erlang:system_time(seconds) + ?DEFAULT_EXPIRY,
	case TokenExpiryTimestamp of
		0 ->
			DefaultExpiryTimestamp;
        Value ->
			if Value > DefaultExpiryTimestamp ->
				DefaultExpiryTimestamp;
			true ->
				Value
			end
	end.

determine_expiry_bucket(ExpiryTimestamp) ->
	ExpiryTimestamp div 3600 * 3600 + 3600.

