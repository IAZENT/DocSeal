#!/usr/bin/env bash
# Bash completion for docseal CLI

_docseal_completions() {
    local cur prev words cword
    _init_completion || return

    # Top-level commands
    local commands="ca sign verify"
    
    # CA subcommands
    local ca_commands="init issue revoke list info"
    
    case "${COMP_CWORD}" in
        1)
            COMPREPLY=($(compgen -W "${commands} --help --version" -- "${cur}"))
            return 0
            ;;
        2)
            if [[ "${prev}" == "ca" ]]; then
                COMPREPLY=($(compgen -W "${ca_commands} --help" -- "${cur}"))
                return 0
            elif [[ "${prev}" == "sign" ]]; then
                COMPREPLY=($(compgen -W "--doc --cert --out --password --help" -- "${cur}"))
                return 0
            elif [[ "${prev}" == "verify" ]]; then
                COMPREPLY=($(compgen -W "--doc --sig --ca --no-revocation-check --no-audit --verbose --help" -- "${cur}"))
                return 0
            fi
            ;;
        3)
            if [[ "${words[1]}" == "ca" ]]; then
                case "${words[2]}" in
                    init)
                        COMPREPLY=($(compgen -W "--password --force --help" -- "${cur}"))
                        return 0
                        ;;
                    issue)
                        COMPREPLY=($(compgen -W "--name --role --validity --out --password --help" -- "${cur}"))
                        return 0
                        ;;
                    revoke)
                        COMPREPLY=($(compgen -W "--serial --reason --help" -- "${cur}"))
                        return 0
                        ;;
                    list|info)
                        COMPREPLY=($(compgen -W "--help" -- "${cur}"))
                        return 0
                        ;;
                esac
            fi
            ;;
    esac

    # File completion for document and certificate paths
    case "${prev}" in
        --doc|--cert|--sig|--ca|--out)
            COMPREPLY=($(compgen -f -- "${cur}"))
            return 0
            ;;
    esac

    return 0
}

complete -F _docseal_completions docseal
