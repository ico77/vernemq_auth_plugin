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
	ExpiryTimestamp = determine_expiry_timestamp(Token),
	maps:put(<<"exp">>, ExpiryTimestamp, Token),
	ExpiryBucket = determine_expiry_bucket(ExpiryTimestamp),
	gen_server:call(?MODULE, {store, ClientId, Token, ExpiryTimestamp, ExpiryBucket}).

-spec lookup(binary()) -> [tuple()].
lookup(ClientId) ->
    ets:lookup(?CACHE, ClientId).

-spec delete(binary()) -> true.
delete(_ClientId) ->
	gen_server:call(?MODULE, {delete}).
	
%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    {ok, #state{}}.

handle_call({store, ClientId, Token, ExpiryTimestamp, ExpiryBucket}, _From, _State) ->
	ets:insert(?CACHE, {ClientId, Token}),
	ets:insert(?EXPIRY, {{ExpiryBucket, ClientId}, true}),
    {reply, {ok}, _State};
handle_call({delete}, _From, _State) ->
	Timestamp = erlang:system_time(seconds),
	MS = ets:fun2ms(fun({{E, C}, _V}) when E < Timestamp -> {E, C} end),
	Expiries = ets:select(?EXPIRY, MS),
	lists:foreach(fun({ExpiryBucket, ClientId}) ->
		ets:match_delete(?EXPIRY, {{ExpiryBucket, ClientId}, '_'}),
		ets:select_delete(?CACHE, ets:fun2ms(fun({C, T}) when C =:= ClientId, map_get(<<"exp">>, T) =< ExpiryBucket -> true end))
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
determine_expiry_timestamp(Token) ->
	DefaultExpiryTimestamp = erlang:system_time(seconds) + ?DEFAULT_EXPIRY,
	case maps:find(<<"exp">>, Token) of
		{ok, Value} ->
			if Value > DefaultExpiryTimestamp ->
				DefaultExpiryTimestamp;
			true ->
				Value
			end;
		_ ->
			DefaultExpiryTimestamp
	end.

determine_expiry_bucket(ExpiryTimestamp) ->
	ExpiryTimestamp div 3600 * 3600 + 3600.

