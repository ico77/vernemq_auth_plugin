-module(vernemq_auth_plugin_subscribe).

-export([authorize_topics/2]).

authorize_topics([], _ClaimsTopics) ->
    ok;
authorize_topics([Topic | Rest], ClaimsTopics) ->
    case check_subscribe_claims(Topic, ClaimsTopics) of
        ok ->
            authorize_topics(Rest, ClaimsTopics);
        {error, Reason} ->
            {error, Reason}
    end.

check_subscribe_claims(_, []) ->
    {error, subscribe_not_allowed};
check_subscribe_claims({Topic, _QoS}, [Claim | Rest]) ->
    case check_subscribe_claim(Topic, Claim) of
        true ->
            ok;
        false ->
            check_subscribe_claims(Topic, Rest)
    end.

check_subscribe_claim(Topic, {ClaimAction, ClaimTopic}) ->
    IsActionAllowed = ClaimAction =:= subscribe,
    SplittedTopic = vernemq_auth_plugin_topic:word(ClaimTopic),
    IsTopicAllowed = vernemq_auth_plugin_topic:match(Topic, SplittedTopic),

    IsActionAllowed andalso IsTopicAllowed.
