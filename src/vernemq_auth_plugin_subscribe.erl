-module(vernemq_auth_plugin_subscribe).

-export([authorize/3]).

authorize(ClientId, Topics, Token) ->
    authorize_topics(Topics, Token).

authorize_topics([], Token) ->
    ok;
authorize_topics([Topic | Rest], Token) ->
    case authorize_single_topic(Topic, Token) of
        ok ->
            authorize_topics(Rest, Token);
        {error, Reason} ->
            {error, Reason}
    end.

authorize_single_topic({_Topic, _QoS} = Topic, Token) ->
    case maps:find(<<"topic-claims">>, Token) of
        {ok, Claims} ->
            check_subscribe_claims(_Topic, Claims);
        _ ->
            {error, claims_missing}
    end.

check_subscribe_claims(_, []) ->
    {error, subscribe_not_allowed};
check_subscribe_claims(Topic, [Claim | Rest]) ->
    case check_subscribe_claim(Topic, Claim) of
        true ->
            ok;
        false ->
            check_subscribe_claims(Topic, Rest)
    end.

check_subscribe_claim(Topic, Claim) ->
    IsActionAllowed =
        case maps:find(<<"action">>, Claim) of
            {ok, <<"subscribe">>} ->
                true;
            _ ->
                false
        end,
    IsTopicAllowed =
        case maps:find(<<"topic">>, Claim) of
            {ok, ClaimTopic} ->
                SplittedTopic = vernemq_auth_plugin_topic:word(ClaimTopic),
                vernemq_auth_plugin_topic:match(Topic, SplittedTopic);
            _ ->
                false
        end,
    IsActionAllowed andalso IsTopicAllowed.
