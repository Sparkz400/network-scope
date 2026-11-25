//! `completions powershell|bash|zsh|fish`: prints a shell completion script generated from the
//! option and command tables, so new commands and options are completed without touching this
//! file. Every script offers the commands as the first word and the options after it, file
//! names after the options in [`FILE_VALUES`] and the [`FORMATS`] after `--format`.
use super::names;
use crate::ui::{
    Ctx,
    args::{FLAGS, VALUES},
    output,
};

/// Options that take a file name (completed with file names).
const FILE_VALUES: [&str; 20] = [
    "output",
    "db",
    "pcap",
    "script",
    "probes",
    "alerts",
    "cves",
    "feeds",
    "kev",
    "epss",
    "targets-file",
    "scope-file",
    "zones",
    "model",
    "record",
    "nvd",
    "csaf",
    "sboms",
    "vex",
    "on-alert",
];
/// Every value a `--format` of some command accepts (each command takes its own subset).
const FORMATS: &str = "json csv html nmap md jsonl cyclonedx lines text ascii dot tsv compliance-iec62443 compliance-nis2 compliance-cis compliance-iec62443-csv compliance-nis2-csv compliance-cis-csv netbox netbox-devices snipeit splunk elastic servicenow";
const SHELLS: &str = "bash zsh fish powershell";
pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    output(
        completions(
            ctx.pos
                .first()
                .ok_or("Provide the shell: powershell, bash, zsh or fish")?,
        )?
        .trim_end(),
        &ctx.opts,
    )
}
fn completions(shell: &str) -> Result<String, String> {
    let commands = names().join(" ");
    let options = FLAGS
        .iter()
        .chain(VALUES.iter())
        .map(|o| format!("--{o}"))
        .collect::<Vec<_>>();
    let values = VALUES.iter().map(|o| format!("--{o}")).collect::<Vec<_>>();
    let files = FILE_VALUES
        .iter()
        .map(|o| format!("--{o}"))
        .collect::<Vec<_>>();
    let quoted = |list: &[String]| {
        list.iter()
            .map(|o| format!("'{o}'"))
            .collect::<Vec<_>>()
            .join(",")
    };
    match shell {
        "bash" => Ok(format!(
            r#"# network-scope completion for bash. Load with: source <(network-scope completions bash)
_network_scope() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    local prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    local values=" {values} "
    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "{commands} --quiet" -- "$cur") )
        return
    fi
    case "$prev" in
        --format) COMPREPLY=( $(compgen -W "{FORMATS}" -- "$cur") ); return ;;
        {file_case}) COMPREPLY=( $(compgen -f -- "$cur") ); return ;;
    esac
    if [[ "$values" == *" $prev "* ]]; then
        return
    fi
    if [[ "${{COMP_WORDS[1]}}" == completions ]]; then
        COMPREPLY=( $(compgen -W "{SHELLS}" -- "$cur") )
        return
    fi
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "{options}" -- "$cur") )
    fi
}}
complete -o default -F _network_scope network-scope network-scope.exe network-scope-cli network-scope-cli.exe
"#,
            values = values.join(" "),
            options = options.join(" "),
            file_case = files.join("|"),
        )),
        "powershell" => Ok(format!(
            r#"# network-scope completion for PowerShell. Load with:
#   network-scope completions powershell | Out-String | Invoke-Expression
Register-ArgumentCompleter -Native -CommandName 'network-scope','network-scope.exe','network-scope-cli','network-scope-cli.exe' -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    $commands = @({commands_q},'--quiet')
    $options = @({options_q})
    $values = @({values_q})
    $formats = @('{formats_q}')
    $words = @($commandAst.CommandElements | ForEach-Object {{ $_.ToString() }})
    $before = $words.Count
    if ($wordToComplete -ne '') {{ $before-- }}
    $prev = if ($before -ge 1) {{ $words[$before - 1] }} else {{ '' }}
    if ($before -le 1) {{ $candidates = $commands }}
    elseif ($prev -eq '--format') {{ $candidates = $formats }}
    elseif ($values -contains $prev) {{ return }}
    elseif ($words[1] -eq 'completions') {{ $candidates = @('{shells_q}') }}
    elseif ($wordToComplete -eq '' -or $wordToComplete.StartsWith('-')) {{ $candidates = $options }}
    else {{ return }}
    $candidates | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
}}
"#,
            commands_q = quoted(&names().iter().map(|c| c.to_string()).collect::<Vec<_>>()),
            options_q = quoted(&options),
            values_q = quoted(&values),
            formats_q = FORMATS.replace(' ', "','"),
            shells_q = SHELLS.replace(' ', "','"),
        )),
        "zsh" => Ok(format!(
            r#"# network-scope completion for zsh. Load with (after compinit):
#   source <(network-scope completions zsh)
_network_scope() {{
    local cur="${{words[CURRENT]}}"
    local prev="${{words[CURRENT-1]}}"
    local -a values=({values})
    if (( CURRENT == 2 )); then
        compadd -- {commands} --quiet
        return
    fi
    case "$prev" in
        --format) compadd -- {FORMATS}; return ;;
        {file_case}) _files; return ;;
    esac
    if (( ${{values[(Ie)$prev]}} )); then
        return
    fi
    if [[ "${{words[2]}}" == completions ]]; then
        compadd -- {SHELLS}
        return
    fi
    if [[ "$cur" == -* ]]; then
        compadd -- {options}
    else
        _files
    fi
}}
compdef _network_scope network-scope network-scope.exe network-scope-cli network-scope-cli.exe
"#,
            values = values.join(" "),
            options = options.join(" "),
            file_case = files.join("|"),
        )),
        "fish" => {
            // One `complete` line per option: a switch, a value completed with the formats or
            // with file names, or a value that is typed (nothing to offer).
            let after = "-n __network_scope_after_command ";
            let mut lines = vec![
                format!("-n __network_scope_at_command -f -a '{commands}'"),
                format!("-n '__fish_seen_subcommand_from completions' -f -a '{SHELLS}'"),
            ];
            for flag in FLAGS {
                // `--quiet` is also accepted before the command.
                let when = if flag == "quiet" { "" } else { after };
                lines.push(format!("{when}-l {flag}"));
            }
            for value in VALUES {
                lines.push(if value == "format" {
                    format!("{after}-l format -x -a '{FORMATS}'")
                } else if FILE_VALUES.contains(&value) {
                    format!("{after}-l {value} -r -F")
                } else {
                    format!("{after}-l {value} -x")
                });
            }
            let lines: String = lines
                .iter()
                .map(|l| format!("    complete -c $c {l}\n"))
                .collect();
            Ok(format!(
                r#"# network-scope completion for fish. Load with:
#   network-scope completions fish | source
function __network_scope_at_command
    test (count (commandline -opc)) -eq 1
end
function __network_scope_after_command
    test (count (commandline -opc)) -gt 1
end
for c in network-scope network-scope.exe network-scope-cli network-scope-cli.exe
{lines}end
"#
            ))
        }
        _ => Err("Choose powershell, bash, zsh or fish".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completions_cover_every_command_and_option() {
        for shell in SHELLS.split(' ') {
            let script = completions(shell).unwrap();
            for c in names() {
                assert!(script.contains(c), "{shell}: {c}");
            }
            for o in FLAGS.iter().chain(VALUES.iter()) {
                // fish names a long option without the dashes: `complete ... -l quiet`.
                let found = if shell == "fish" {
                    script.lines().any(|l| {
                        l.ends_with(&format!(" -l {o}")) || l.contains(&format!(" -l {o} "))
                    })
                } else {
                    script.contains(&format!("--{o}"))
                };
                assert!(found, "{shell}: --{o}");
            }
            // The shells themselves (after `completions`) and the format values.
            assert!(script.contains("zsh") && script.contains("fish"), "{shell}");
            assert!(script.contains("compliance-nis2-csv"), "{shell}");
            // A format string that lost a brace would show here.
            assert_eq!(
                script.matches('{').count(),
                script.matches('}').count(),
                "{shell}"
            );
        }
        assert!(
            completions("bash")
                .unwrap()
                .contains("complete -o default -F _network_scope")
        );
        assert!(
            completions("powershell")
                .unwrap()
                .contains("Register-ArgumentCompleter -Native")
        );
        let zsh = completions("zsh").unwrap();
        assert!(zsh.contains("compdef _network_scope network-scope "));
        assert!(zsh.contains("|--targets-file|") && zsh.contains(") _files; return ;;"));
        let fish = completions("fish").unwrap();
        for line in [
            "    complete -c $c -n __network_scope_at_command -f -a 'feeds scan ",
            "    complete -c $c -l quiet\n",
            "    complete -c $c -n __network_scope_after_command -l tcp-only\n",
            "    complete -c $c -n __network_scope_after_command -l ports -x\n",
            "    complete -c $c -n __network_scope_after_command -l db -r -F\n",
            "    complete -c $c -n __network_scope_after_command -l format -x -a 'json csv ",
        ] {
            assert!(fish.contains(line), "{line}");
        }
        assert!(completions("tcsh").is_err());
        for f in FILE_VALUES {
            assert!(VALUES.contains(&f), "--{f}");
        }
        // Every export target is offered, and every offered format is one some command takes.
        let formats: Vec<&str> = FORMATS.split(' ').collect();
        for target in crate::sync::Target::ALL {
            assert!(formats.contains(&target.name()), "{}", target.name());
        }
        for format in &formats {
            let known = crate::sync::Target::parse(format).is_some()
                || network_scope_core::compliance::Standard::from_format(format).is_some()
                || [
                    "json",
                    "csv",
                    "html",
                    "nmap",
                    "md",
                    "jsonl",
                    "cyclonedx",
                    "lines",
                    "text",
                    "ascii",
                    "dot",
                    "tsv",
                ]
                .contains(format);
            assert!(known, "{format}");
        }
    }
}
