-module(vernemq_auth_plugin_config).

-export([load/0]).

load() ->
    File = filename:join([code:priv_dir(vernemq_auth_plugin), "vernemq_auth_plugin.conf"]),
    {ok, Text} = file:read_file(File),
    error_logger:info_msg("Config: ~p", [Text]),
    {ok, Ts, _} = erl_scan:string(binary_to_list(Text)),
    {ok, Config} = erl_parse:parse_term(Ts),
    [{signing_key, SigningKey} | _] = Config,
    error_logger:info_msg("Parsed config: ~p", [SigningKey]),
    application:set_env(vernemq_auth_plugin, signing_key, SigningKey).
