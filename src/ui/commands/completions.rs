//! `completions powershell|bash`: prints a shell completion script generated from the option and
//! command tables, so new commands and options are completed without touching this file.
use super::names;
use crate::ui::{
    Ctx,
    args::{FLAGS, VALUES},
    output,
};

/// Options that take a file name (completed with file names).
const FILE_VALUES: [&str; 10] = [
    "output", "db", "pcap", "script", "probes", "alerts", "cves", "feeds", "kev", "epss",
];
const FORMATS: &str = "json csv html nmap md jsonl lines text ascii dot";
pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    output(
        completions(
            ctx.pos
                .first()
                .ok_or("Provide the shell: powershell or bash")?,
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
        COMPREPLY=( $(compgen -W "bash powershell" -- "$cur") )
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
    elseif ($words[1] -eq 'completions') {{ $candidates = @('bash','powershell') }}
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
        )),
        _ => Err("Choose powershell or bash".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completions_cover_every_command_and_option() {
        for shell in ["bash", "powershell"] {
            let script = completions(shell).unwrap();
            for c in names() {
                assert!(script.contains(c), "{shell}: {c}");
            }
            for o in FLAGS.iter().chain(VALUES.iter()) {
                assert!(script.contains(&format!("--{o}")), "{shell}: --{o}");
            }
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
        assert!(completions("fish").is_err());
        for f in FILE_VALUES {
            assert!(VALUES.contains(&f), "--{f}");
        }
    }
}
