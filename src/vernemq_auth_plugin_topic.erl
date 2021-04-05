-module(vernemq_auth_plugin_topic).

-export([word/1, match/2]).

-type token() :: binary().
-type topic() :: [token()].

word(Topic) ->
    re:split(Topic, <<"/">>).

-spec match(MatchSource :: topic(), MatchTarget :: topic()) -> boolean().
match([], []) ->
    true;
match([H | T1], [H | T2]) ->
    match(T1, T2);
match([_H | T1], [<<"+">> | T2]) ->
    match(T1, T2);
match(_, [<<"#">>]) ->
    true;
match([_H1 | _], [_H2 | _]) ->
    false;
match([], [_H | _T2]) ->
    false;
match(_, _) ->
    false.
