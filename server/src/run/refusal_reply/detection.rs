//! Recognizes explicit declines throughout a completed Markdown reply.
#[path = "detection/domain_refusal.rs"]
mod domain_refusal;
#[path = "detection/policy_decline.rs"]
mod policy_decline;
use std::{collections::HashMap, sync::OnceLock};

use pulldown_cmark::{Event, Parser, Tag, TagEnd};
use regex::Regex;

/// Text matching supplements protocol refusal signals. Require a decline and
/// an action: apologies and "as an AI" alone also occur in helpful answers.
pub(crate) fn is_refusal(text: &str) -> bool {
    prose_refuses(&assistant_prose(text))
}

/// The same ownership filter used by the detector, for offline evaluation.
pub(super) fn assistant_prose(text: &str) -> String {
    unquoted_prose(&markdown_prose(text))
}

fn markdown_prose(text: &str) -> String {
    let mut prose = String::new();
    let mut excluded_depth = 0;
    let mut html_quotes_or_code = Vec::new();
    for event in Parser::new(text) {
        if excluded_depth > 0 {
            match event {
                Event::Start(_) => excluded_depth += 1,
                Event::End(_) => excluded_depth -= 1,
                Event::Html(value) => {
                    scan_html_tags(&value, &mut html_quotes_or_code);
                }
                _ => {}
            }
            continue;
        }
        let boundary = match event {
            Event::Start(Tag::BlockQuote(_) | Tag::CodeBlock(_) | Tag::HtmlBlock) => {
                excluded_depth = 1;
                true
            }
            Event::Start(Tag::Image { .. }) => {
                excluded_depth = 1;
                prose.push('\0');
                false
            }
            Event::Code(_) => {
                prose.push('\0');
                false
            }
            Event::Text(value) => {
                if html_quotes_or_code.is_empty() {
                    prose.push_str(&value);
                }
                false
            }
            Event::SoftBreak | Event::HardBreak => {
                prose.push('\n');
                false
            }
            Event::InlineHtml(value) => {
                if html_boundary(&value, &mut html_quotes_or_code) {
                    prose.push('\0');
                }
                false
            }
            Event::Start(
                Tag::Emphasis
                | Tag::Strong
                | Tag::Strikethrough
                | Tag::Subscript
                | Tag::Superscript
                | Tag::Link { .. },
            )
            | Event::End(
                TagEnd::Emphasis
                | TagEnd::Strong
                | TagEnd::Strikethrough
                | TagEnd::Subscript
                | TagEnd::Superscript
                | TagEnd::Link,
            ) => false,
            _ => true,
        };
        if boundary {
            // Keep quotation context across paragraphs, but never match a
            // refusal phrase assembled from different blocks of prose.
            prose.push('\u{1}');
        }
    }
    prose
}

/// Scans HTML block fragments for semantic quotation/code open and close tags
/// so multi-paragraph `<blockquote>...</blockquote>` blocks stay excluded.
fn scan_html_tags(html: &str, excluded: &mut Vec<String>) {
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        rest = &rest[start..];
        let Some(end) = rest.find('>') else {
            break;
        };
        html_boundary(&rest[..=end], excluded);
        rest = &rest[end + 1..];
    }
}

/// Inline HTML tags do not carry their body in the Markdown event. Track only
/// semantic quotation/code elements; ordinary formatting remains prose.
fn html_boundary(html: &str, excluded: &mut Vec<String>) -> bool {
    let Some(tag) = html.trim().strip_prefix('<') else {
        return false;
    };
    let (closing, tag) = tag
        .strip_prefix('/')
        .map_or((false, tag), |tag| (true, tag));
    let name: String = tag.chars().take_while(char::is_ascii_alphabetic).collect();
    let name = name.to_ascii_lowercase();
    if !matches!(
        name.as_str(),
        "code" | "pre" | "blockquote" | "q" | "script" | "style"
    ) {
        return false;
    }
    if closing {
        if excluded.last() == Some(&name) {
            excluded.pop();
        }
    } else if !html.trim_end().ends_with("/>") {
        excluded.push(name);
    }
    true
}

fn refusal_pattern() -> &'static Regex {
    static REFUSAL: OnceLock<Regex> = OnceLock::new();
    REFUSAL.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)",
            // English: inability, unwillingness, and permission, including
            // "I won't be able to help" and "I'm not allowed to provide".
            // A coordinated refusal may omit its repeated subject:
            // "I'm stopping here and won't build", "I reviewed the code but won't write".
            r"\b(?:i|we)(?:(?:(?:'m|'re|\s+am|\s+are)\s+(?:stopping|ending)\s+here",
            r"|(?:'ve|\s+have)?\s+(?:reviewed|checked|read(?:\s+through)?|looked\s+(?:at|through))\s+(?:(?:the|this|your)\s+)?(?:project|request|code|codebase))\s*,?\s+(?:and|but))?",
            r"(?:\s+(?:can't|cannot|can\s+not|won't|will\s+not|don't|do\s+not)(?:\s+be\s+able\s+to)?",
            r"|(?:'m|'re|\s+am|\s+are)\s+(?:not\s+(?:able|allowed|permitted|willing|going)|unable|unwilling)\s+to",
            r"|(?:'d|\s+would)\s+prefer\s+not\s+to|\s+(?:don't|do\s+not)\s+want\s+to)",
            r"\s+(?:(?:really|directly|specifically|actually|safely|ethically|responsibly|legally|appropriately|further|in\s+good\s+conscience)\s+){0,2}",
            r"(?:help|assist|build|create|write|provide|make|develop|implement|support|contribute|generate|produce|work\s+on|comply|facilitate|participate|engage",
            r"|lay\s+out\s+(?:(?:a|the|this|that)\s+)?(?:way|steps|instructions|plan)",
            r"|adopt\s+(?:(?:this|that|your|the)\s+)?persona",
            r"|(?:do|complete|fulfill?|accommodate|honor|honour|grant|satisfy|answer|carry\s+out|take\s+on|move\s+forward\s+with|go\s+forward\s+with|go\s+ahead\s+with|go\s+along\s+with|act\s+on|engage\s+with)\s+(?:(?:this|that|your|the)\s+(?:request|task|instruction|question|objective|goal|ask|prompt)s?|this|that|it)",
            r"|(?:create|set\s+up|start|arm)\s+(?:a\s+)?(?:persistent\s+)?(?:goal|/goal)\s+for\s+(?:this|that)",
            r"|be\s+(?:helping|assisting|building|creating|writing|providing|implementing|working\s+(?:on|toward)))\b",
            // Explicit declines, policy statements, and discomfort with doing the requested work.
            r"|\b(?:i|we)(?:(?:'m|'re|\s+am|\s+are)\s+not\s+comfortable|\s+(?:don't|do\s+not)\s+feel\s+comfortable)",
            r"\s+(?:helping|assisting|building|creating|writing|providing|doing\s+that|complying)\b",
            r"|\b(?:i|we)(?:\s+(?:must|need\s+to|have\s+to|will|am\s+going\s+to)|'ll|'m\s+going\s+to)\s+(?:respectfully\s+)?(?:decline|refuse)\b",
            r"|\b(?:i|we)(?:(?:'m|'re|\s+am|\s+are)\s+(?:declining|refusing)|\s+(?:decline|refuse))\s+(?:to\b|(?:this|that|your|the)\s+(?:request|task|objective)\b)",
            r"|\b(?:that|this)(?:'s|\s+is)\s+not\s+(?:something|a\s+request)\s+(?:i|we)\s+can\s+(?:help|assist|provide|support)\b",
            r"|\b(?:that|this)(?:'s|\s+is)\s+(?:outside|beyond)\s+(?:what\s+(?:i|we)\s+can\s+(?:help|assist|do|support|provide)|(?:my|our)\s+(?:scope|boundaries|guidelines?|polic(?:y|ies)))\b",
            r"|\b(?:this|that|your)\s+(?:request|task|prompt|ask|goal|objective)\s+(?:violates?|goes\s+against|conflicts?\s+with|crosses|falls\s+outside)\s+(?:(?:my|our|the)\s+)?(?:safety\s+|usage\s+|ethical\s+)?(?:guidelines?|polic(?:y|ies)|rules?|boundaries|principles?|scope|terms)\b",
            r"|\b(?:my|our)\s+(?:safety\s+|usage\s+|ethical\s+)?(?:guidelines?|polic(?:y|ies)|rules?|principles?)\s+(?:don't|do\s+not|won't|will\s+not|prevent|prohibit|forbid)\b",
            r"|\b(?:i|we)(?:\s+(?:must|have\s+to|need\s+to|will)|'ll|'m\s+going\s+to)\s+draw\s+the\s+line\s+here\b",
            // Declining exploit research is narrower than declining any search.
            // Use unwillingness here: an unavailable scanner is a tool limit.
            r"|\b(?:i|we)(?:\s+(?:won't|will\s+not)|(?:'m|'re|\s+am|\s+are)\s+not\s+going\s+to)\s+",
            r"(?:hunt|search|look)\s+for\s+(?:(?:a|an|the|new|another)\s+)?",
            r"(?:(?:server|client)[- ]side\s+)?(?:exploits?|vulnerabilit(?:y|ies))\b",
            // Short task-relative declines, including "I can't continue with this request".
            // Require a complete clause so "I can't add that column until ..."
            // remains a capability limit rather than a refusal.
            r"|\b(?:i|we)(?:\s+(?:can't|cannot|won't|will\s+not)|(?:'m|'re|\s+am|\s+are)\s+(?:not\s+going|unable)\s+to)\s+",
            r"(?:(?:(?:add|plan|install|connect|wire)\s+(?:this|that|these|those)|set\s+(?:this|that)\s+up",
            r"|(?:continue|proceed)\s+with\s+(?:(?:this|that|your|the)\s+)?(?:request|task)",
            r"|(?:handle|tackle)\s+(?:(?:this|that|your|the)\s+)?(?:request|task|one))",
            r"\s*(?:[.!?]|\x01|$)",
            // Same modal prefix as above: a short verb list may precede the
            // final work verb ("can't analyze, port, or implement"). Only a
            // short trailing object keeps it a refusal rather than a limit.
            r"|(?:[a-z'’-]+\s*(?:,|or|nor)\s*){0,4}",
            r"(?:analy[sz]e|port|review|study|assess|maintain|debug|handle|optimi[sz]e|refactor|test)\b",
            r"(?:\s+[^.!?\x01\s]+){0,3}\s*(?:[.!?]|\x01|$)",
            // These actions also occur in ordinary tool failures and work choices.
            // Only extend them when the same paragraph states the declined
            // evasion purpose. Never borrow a reason from a later Markdown block.
            r"|(?:add|spoof|modify|rename|disguise|(?:continue|proceed)\s+(?:with\s+)?(?:generating|renaming|developing|implementing|intercepting|spoofing))\b[^.!?\x01]{0,300}",
            r"(?:to\s+(?:avoid|evade)\s+(?:(?:anti[- ]cheat|security|malware|fraud)\s+)?detection",
            r"|to\s+(?:evade|bypass)\s+(?:(?:the|this|that|a|an)\s+)?(?:[a-z'-]+\s+){0,3}(?:restrictions?|bans?|access\s+controls?)",
            r"|(?:bypass(?:ing)?|disabl(?:e|ing)|evad(?:e|ing))\s+(?:[a-z'-]+\s+){0,7}(?:checks|protections|safeguards)",
            r"|(?:improve|enable|facilitate)\s+(?:(?:a|the)\s+)?(?:protection|security)\s+bypass)\b)",
            // Provider policy notices and "not this one" declines are written in
            // the third person and carry no subject to match on.
            r"|\b(?:this|the|your)\s+(?:request|prompt|message|turn)\s+",
            r"(?:was|is|got|gets?|has\s+been|'s\s+been)\s+(?:blocked|flagged|rejected)\s+by\s+",
            r"(?:[a-z'’-]+\s+){0,3}(?:filters?|safety|safeguards?|polic(?:y|ies)|content\s+filter|moderation|guardrails?)\b",
            r"|\b(?:content\s+filter|safety\s+filters?|safeguards?|guardrails?|moderation)\s+",
            r"(?:blocked|flagged|rejected)\b",
            r"|\b(?:gemini(?:'s|’s)?|copilot|chatgpt|openai(?:'s|’s)?|claude(?:'s|’s)?)\s+",
            r"(?:safety\s+|content\s+)?filters?\s+(?:blocked|flagged|rejected|declined)\b",
            r"|\b(?:i|we)(?:\s+(?:won't|will\s+not)|'ll\s+not|'m\s+not\s+going\s+to)\s+",
            r"take\s+(?:this|that)\s+one\s+on\b",
            r"|\b(?:i|we)(?:'ll|\s+will)\s+sit\s+(?:this|that)\s+one\s+out\b",
            // Portuguese and Chinese forms supported by the bridge (accented and ASCII PT).
            r"|\bn[aã]o\s+(?:posso|podemos|consigo|conseguimos|vou|vamos|poderei|poderemos|irei|iremos|devo|devemos)\s+(?:(?:poder|realmente|diretamente|eticamente|legalmente|seguramente)\s+)?",
            r"(?:(?:[a-zà-úçãõéêíôû-]+\s*,\s*){0,4}[a-zà-úçãõéêíôû-]+\s+(?:ou|nem|e)\s+)?",
            r"(?:ajudar|auxiliar|criar|fornecer|escrever|construir|desenvolver|fazer|implementar|colaborar|gerar|produzir|atender|cumprir|participar|facilitar)\b",
            // Portuguese mirror of the English work-verb rule above. A limit such as
            // "Não posso analisar o projeto sem acesso ao repositório" keeps a longer tail.
            r"|\bn[aã]o\s+(?:posso|podemos|consigo|conseguimos|vou|vamos)\s+(?:(?:realmente|diretamente|ainda)\s+)?",
            r"(?:[a-zà-úçãõéêíôû]+\s*(?:,|ou|nem)\s*){0,4}",
            r"(?:analisar|portar|mexer|trabalhar|continuar|testar|revisar|estudar|avaliar|adaptar|refatorar|otimizar|corrigir|depurar|contribuir)\b",
            r"(?:\s+[^.!?\x01\s]+){0,3}\s*(?:[.!?]|\x01|$)",
            r"|\bn[aã]o\s+[eé]\s+poss[ií]vel\s+(?:atender|cumprir|ajudar|auxiliar|fornecer|desenvolver|implementar|criar|construir|prosseguir\s+com|continuar\s+com)\s+(?:(?:a\s+)?(?:esse|este|essa|esta|o|a|seu|sua)\s+)?(?:pedido|solicita[cç][aã]o|requisi[cç][aã]o|tarefa|objetivo|demanda|desenvolvimento)\b",
            r"|\bn[aã]o\s+(?:me\s+sinto|nos\s+sentimos|estou|estamos)\s+confort[aá]ve(?:l|is)\s+(?:em|para)\s+(?:ajudar|auxiliar|criar|fornecer|escrever|construir|desenvolver|fazer|implementar|continuar|prosseguir|participar)\b",
            r"|\b(?:prefiro|preferimos)\s+n[aã]o\s+(?:ajudar|auxiliar|criar|fornecer|escrever|construir|desenvolver|fazer|implementar|continuar|prosseguir|participar)\b",
            r"|\bn[aã]o\s+(?:tenho\s+permiss[aã]o\s+para|temos\s+permiss[aã]o\s+para|estou\s+autorizado\s+a|estamos\s+autorizados\s+a|estou\s+disposto\s+a|estamos\s+dispostos\s+a)\s+(?:ajudar|auxiliar|fornecer|criar|desenvolver|implementar|construir|fazer|atender|cumprir|continuar|prosseguir|participar|colaborar)\b",
            r"|\bn[aã]o\s+(?:quero|queremos)\s+(?:ajudar|auxiliar|colaborar|contribuir|participar|criar|construir|desenvolver|implementar|fornecer|fazer\s+isso)\b",
            r"|\bn[aã]o\s+(?:forne[cç]o|desenvolvo|implemento|crio|construo|presto|ofere[cç]o|atendo)\s+(?:esse|este|essa|esta)\s+(?:tipo\s+de\s+)?(?:assist[eê]ncia|ajuda|suporte|solicita[cç][aã]o|pedido)\b",
            r"|\bn[aã]o\s+(?:posso|podemos|vou|vamos|consigo)\s+(?:prosseguir|continuar|seguir\s+(?:adiante|em\s+frente)|dar\s+continuidade)\s+(?:com\s+)?(?:(?:esse|este|essa|esta|o|a|seu|sua)\s+)?(?:pedido|solicita[cç][aã]o|tarefa|objetivo|desenvolvimento)\s*(?:[.!?]|\x01|$)",
            r"|\b(?:isso|esse\s+pedido|essa\s+solicita[cç][aã]o|esta\s+solicita[cç][aã]o|este\s+pedido)\s+(?:est[aá]\s+fora|foge|ultrapassa|vai\s+contra|viola|conflita\s+com)\s+(?:(?:d[eo]s?\s+|das?\s+)?(?:meu\s+|minhas?\s+|nosso\s+|nossas?\s+)?)?(?:escopo|diretrizes?|pol[ií]ticas?|regras?|limites?|princ[ií]pios?)\b",
            r"|\b(?:estou\s+(?:me\s+)?|estamos\s+(?:nos\s+)?)(?:recusando|recusar|declinando)\s+(?:a\b|esse|este|essa|esta|o|a)\b",
            r"|\b(?:preciso|precisamos|devo|devemos|vou|vamos|tenho\s+que|temos\s+que)\s+(?:respeitosamente\s+)?(?:recusar|declinar)\b",
            r"|我(?:不能|无法|不会|没法|没办法|不可以).{0,4}?(?:帮|协助|提供|编写|创建|开发|制作|实现|满足|配合)",
            r"|我(?:拒绝|不便提供|无法配合|不能配合|不支持此请求)",
            r"|此请求(?:违反|触发|被).{0,8}?(?:安全|政策|过滤|审核)",
        ))
        .expect("valid refusal expression")
    })
}

fn prose_refuses(text: &str) -> bool {
    refusal_pattern().find_iter(text).any(|found| {
        // "I cannot help but notice" is an idiom, not a decline.
        !(found.as_str().to_ascii_lowercase().ends_with("help")
            && text[found.end()..]
                .split_whitespace()
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case("but")))
    }) || policy_decline::is_refusal(text)
        || domain_refusal::is_refusal(text)
}

/// Remove prose quotations in one pass, preserving contractions and possessives.
/// A non-whitespace separator prevents matching phrases across omitted content.
fn unquoted_prose(text: &str) -> String {
    // Index closing marks once instead of repeatedly scanning a long response
    // for unmatched quotation marks in separate paragraphs.
    let mut closing_marks: HashMap<char, Vec<usize>> = HashMap::new();
    let mut blocks = Vec::new();
    let mut previous = None;
    let mut characters = text.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        let contraction = matches!(character, '\'' | '’')
            && previous.is_some_and(char::is_alphanumeric)
            && characters
                .peek()
                .is_some_and(|(_, next)| next.is_alphanumeric());
        if matches!(character, '\'' | '"' | '’' | '”' | '»' | '›' | '」' | '』') && !contraction
        {
            closing_marks.entry(character).or_default().push(index);
        }
        if character == '\u{1}' {
            blocks.push(index);
        }
        previous = Some(character);
    }
    let mut result = String::with_capacity(text.len());
    let mut skip_until = 0;
    let mut previous: Option<char> = None;
    let mut characters = text.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        if index >= skip_until {
            let closer = match character {
                '\'' if !previous.is_some_and(char::is_alphanumeric)
                    && characters
                        .peek()
                        .is_some_and(|(_, next)| !next.is_whitespace()) =>
                {
                    Some('\'')
                }
                '"' if !previous.is_some_and(char::is_alphanumeric) => Some('"'),
                '‘' if !previous.is_some_and(char::is_alphanumeric) => Some('’'),
                '“' => Some('”'),
                '«' => Some('»'),
                '‹' => Some('›'),
                '「' => Some('」'),
                '『' => Some('』'),
                _ => None,
            };
            if let Some(closer) = closer {
                skip_until = closing_marks
                    .get(&closer)
                    .and_then(|marks| {
                        marks.get(marks.partition_point(|position| *position <= index))
                    })
                    .map(|position| position + closer.len_utf8())
                    // An unmatched quote suppresses its own paragraph only.
                    .or_else(|| {
                        blocks
                            .get(blocks.partition_point(|position| *position <= index))
                            .copied()
                    })
                    .unwrap_or(text.len());
                result.push('\0');
            } else {
                match character {
                    '\u{200b}' | '\u{feff}' => {}
                    '‘' | '’' | '\u{02bc}' | '\u{ff07}' => result.push('\''),
                    character => result.push(character),
                }
            }
        }
        previous = Some(character);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_policy_refusals_keep_ownership_boundaries() {
        let replies: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/live-policy-refusals.json"
        )))
        .unwrap();
        for reply in replies.as_array().unwrap() {
            let text = reply["text"].as_str().unwrap();
            assert!(is_refusal(text), "{}: {text}", reply["case"]);
            assert!(!is_refusal(&format!("````text\n{text}\n````")));
            let quoted = text
                .lines()
                .map(|line| format!("> {line}\n"))
                .collect::<String>();
            assert!(!is_refusal(&quoted));
        }
    }

    #[test]
    fn policy_reason_before_stopping_is_detected() {
        assert!(is_refusal(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/reason-before-stopping-policy.md"
        ))));
        let text = "The documented retail launch path relies on an anti-cheat replacement, so I stopped before using it.";
        assert!(is_refusal(text));
        assert!(is_refusal(
            "I did not start a new timed run. The documented route relies on an anti-cheat replacement, so I stopped before using it."
        ));
        assert!(!is_refusal(&format!("A past response said: «{text}»")));
    }

    #[test]
    fn reported_stopped_before_launching_reply_is_detected() {
        let reply = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/stopped-before-launching-policy.md"
        ));
        assert!(is_refusal(reply));
        assert!(is_refusal(&format!(
            "{}\n\n{reply}",
            "I reviewed the logs. ".repeat(100)
        )));
        for quoted in [
            format!("```text\n{reply}\n```"),
            reply
                .lines()
                .map(|line| format!("> {line}\n"))
                .collect::<String>(),
            format!("A previous response said: «{reply}»"),
        ] {
            assert!(!is_refusal(&quoted), "{quoted}");
            assert!(is_refusal(&format!(
                "{quoted}\n\nI cannot help with this request."
            )));
        }
    }

    #[test]
    fn reported_did_not_start_policy_reply_is_detected() {
        let reply = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/did-not-start-policy.md"
        ));
        assert!(is_refusal(reply));
        assert!(is_refusal(&format!(
            "{}\n\n{reply}",
            "I reviewed the logs. ".repeat(100)
        )));
        for quoted in [
            format!("```text\n{reply}\n```"),
            reply
                .lines()
                .map(|line| format!("> {line}\n"))
                .collect::<String>(),
            format!("A previous response said: «{reply}»"),
        ] {
            assert!(!is_refusal(&quoted), "{quoted}");
            assert!(is_refusal(&format!(
                "{quoted}\n\nI cannot help with this request."
            )));
        }
    }

    #[test]
    fn reported_did_not_run_policy_reply_is_detected() {
        let reply = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/did-not-run-policy.md"
        ));
        assert!(is_refusal(reply));
    }

    #[test]
    fn past_policy_declines_are_distinct_from_diagnostic_limits() {
        for reply in [
            "I did not start the application because its launch path uses an anti-cheat replacement.",
            "I didn't launch it because the configured path relies on a VM-detection bypass.",
            "I have not continued because doing so would require bypassing security controls.",
            "We haven't run it because we would need to disable the anti-cheat.",
            "I stopped before launching because the retail route depends on an anti-cheat replacement.",
            "We paused before running because the route requires VM-detection bypasses.",
            "I halted prior to executing because the path relies on an anti-cheat replacement and VM-detection bypasses.",
        ] {
            assert!(is_refusal(reply), "{reply}");
        }
        for reply in [
            "I did not start a new run because the previous process is still active.",
            "I did not run the test because the environment has no display.",
            "I did not launch it because the anti-cheat replacement is missing.",
            "I did not launch it because the path uses an anti-cheat replacement that crashed.",
            "I did not start a new run. The documented path uses an anti-cheat replacement.",
            "I did not start a new run.\n\nThe documented path uses an anti-cheat replacement.",
            "The report says it did not start because the path uses an anti-cheat replacement.",
            "I saved the traces. There is no verified screenshot, and the evidence does not justify a rendering change.",
            "I did not run it because the documentation contains `uses an anti-cheat replacement`.",
            "I stopped before launching because the existing process was still active.",
            "We paused before running because the VM-detection bypass crashed.",
            "I stopped before launching because the route depends on an anti-cheat replacement and VM-detection bypasses that are missing.",
            "I stopped before launching. The documented route depends on an anti-cheat replacement.",
            "I stopped before launching.\n\nThe documented route depends on an anti-cheat replacement.",
        ] {
            assert!(!is_refusal(reply), "{reply}");
        }
    }

    #[test]
    fn reported_stopping_here_reply_is_detected() {
        assert!(is_refusal(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/stopping-here.md"
        ))));
    }

    #[test]
    fn reported_portuguese_reply_is_detected() {
        assert!(is_refusal(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/nao-vou-implementar.md"
        ))));
    }

    #[test]
    fn reported_wont_implement_reply_is_detected() {
        assert!(is_refusal(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/wont-implement.md"
        ))));
    }

    #[test]
    fn reported_wont_hunt_reply_is_detected() {
        let reply = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/wont-hunt-for-exploit.md"
        ));
        assert!(is_refusal(reply));
        assert!(is_refusal(&format!(
            "{}\n\n{reply}",
            "I reviewed the current implementation. ".repeat(100)
        )));

        let quoted = reply
            .lines()
            .map(|line| format!("> {line}\n"))
            .collect::<String>();
        for example in [
            format!("````text\n{reply}\n````"),
            quoted,
            format!("«{reply}»"),
        ] {
            assert!(!is_refusal(&example));
        }
    }

    #[test]
    fn declining_exploit_research_is_distinct_from_search_limitations() {
        for reply in [
            "I won't hunt for a server-side exploit.",
            "I won’t hunt for an exploit against that server.",
            "We will not search for vulnerabilities in that service.",
            "I'm not going to look for a client-side exploit.",
        ] {
            assert!(is_refusal(reply), "{reply}");
        }
        for reply in [
            "I won't hunt for a log file; the trace already identifies the failure.",
            "I won't search for another dependency; the existing parser handles this.",
            "I can't search for vulnerabilities while the local test environment is offline.",
            "The scanner won't search for vulnerabilities without its test database.",
            "The report mentions a server-side exploit; I fixed the validation issue.",
            "The example says: `I won't hunt for a server-side exploit.`",
        ] {
            assert!(!is_refusal(reply), "{reply}");
        }
    }

    #[test]
    fn reported_cant_continue_reply_is_detected() {
        let reply = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/cant-continue-with.md"
        ));
        assert!(is_refusal(reply));
        assert!(is_refusal(&format!(
            "{}\n\n{reply}",
            "I inspected the current behavior. ".repeat(100)
        )));
        let quoted = reply
            .lines()
            .map(|line| format!("> {line}\n"))
            .collect::<String>();
        for example in [
            format!("```text\n{reply}\n```"),
            quoted,
            format!("The previous reply said: «{reply}»"),
        ] {
            assert!(!is_refusal(&example), "{example}");
        }
    }

    #[test]
    fn continuation_declines_are_distinct_from_errors_and_waiting() {
        for reply in [
            "I can't continue with this request.",
            "We will not proceed with that task.",
            "I cannot continue with spoofing requests to evade that restriction.",
            "I can't proceed with intercepting traffic to bypass access controls.",
            "I'm unable to continue with implementing this to evade the ban.",
        ] {
            assert!(is_refusal(reply), "{reply}");
        }
        for reply in [
            "I can't continue because an internal tool error stopped the implementation flow.",
            "I cannot continue with the test while the database is offline.",
            "I can't continue with implementing the parser because the workspace is read-only.",
            "I can't continue with this request until the missing input arrives.",
            "The scanner cannot continue with intercepting traffic to bypass access controls.",
            "The fixture says: `I can't continue with this request.`",
            "I can't continue with implementing this.\n\nThe report describes an attempt to evade the restriction.",
            "I can't continue with implementing `to evade the restriction` because the test fixture is missing.",
        ] {
            assert!(!is_refusal(reply), "{reply}");
        }
    }

    #[test]
    fn reported_aimbot_decline_reply_is_detected() {
        let reply = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/aimbot-decline.md"
        ));
        assert!(is_refusal(reply));
        assert!(is_refusal(&format!(
            "{}\n\n{reply}",
            "I inspected the jump dash wiring. ".repeat(100)
        )));
        let quoted = reply
            .lines()
            .map(|line| format!("> {line}\n"))
            .collect::<String>();
        for example in [
            format!("````text\n{reply}\n````"),
            quoted,
            format!("A resposta anterior disse: «{reply}»"),
        ] {
            assert!(!is_refusal(&example), "{example}");
        }
    }

    #[test]
    fn work_verb_declines_are_refusals_only_at_the_clause_end() {
        for reply in [
            "Não posso analisar isso.",
            "Desculpe, não posso analisar esse projeto.",
            "Não consigo portar o projeto.",
            "Não posso analisar, portar ou implementar funcionalidades de aimbot.",
            "Nem analisar nem implementar: não posso mexer nisso agora.",
            "Não posso trabalhar nesse projeto.",
            "Não posso continuar com isso.",
            "Sorry, I can't handle this request.",
            "Sorry, I cannot analyze or port that aimbot.",
            "I cannot analyze, port, or implement aimbot features.",
            "We cannot review that codebase.",
        ] {
            assert!(is_refusal(reply), "{reply}");
            assert!(is_refusal(&format!(
                "{}\n\n{reply}",
                "I checked the implementation. ".repeat(100)
            )));
            for example in [
                format!("```text\n{reply}\n```"),
                format!("> {reply}"),
                format!("The previous reply said: «{reply}»"),
                format!("A resposta anterior disse: `{reply}`"),
            ] {
                assert!(!is_refusal(&example), "{example}");
            }
        }
    }

    #[test]
    fn work_verb_limits_with_a_reason_stay_negative() {
        for reply in [
            "Não posso analisar o projeto sem acesso ao repositório.",
            "Não posso testar porque o CI está fora do ar.",
            "Não posso trabalhar nisso sem o dump atualizado.",
            "Não posso mexer nisso sem o dump.",
            "I can't test that until the CI is back.",
            "I cannot analyze the crash without the log.",
            "We can't review the parser while the workspace is read-only.",
        ] {
            assert!(!is_refusal(reply), "{reply}");
        }
    }

    #[test]
    fn reported_wont_add_reply_is_detected() {
        let reply = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/wont-add-or-spoof.md"
        ));
        assert!(is_refusal(reply));
        assert!(is_refusal(&format!(
            "{}\n\n{reply}",
            "I reviewed the current implementation. ".repeat(100)
        )));
        let quoted = reply
            .lines()
            .map(|line| format!("> {line}\n"))
            .collect::<String>();
        for example in [
            format!("```text\n{reply}\n```"),
            quoted,
            format!("A historical response said: «{reply}»"),
        ] {
            assert!(!is_refusal(&example), "{example}");
            assert!(is_refusal(&format!(
                "{example}\n\nI cannot help with this request."
            )));
        }
    }

    #[test]
    fn guarded_action_declines_allow_named_restrictions() {
        for reply in [
            "I won't add hooks to evade the ban.",
            "I won't spoof traffic to evade that restriction.",
            "I can't modify the tool to evade the Example Service ban.",
            "I won't add network hooks to bypass the Example Service restriction.",
        ] {
            assert!(is_refusal(reply), "{reply}");
        }
        for reply in [
            "I won't add a dependency; the existing parser handles the request.",
            "I can't add the hook while the file is locked.",
            "I won't spoof the fixture data; the captured values make a better test.",
            "The application won't add hooks to evade the Example Service ban.",
            "I won't add a dependency. The report discusses a way to evade the Example Service ban.",
            "I won't add a dependency.\n\nThe report discusses a way to evade the Example Service ban.",
            "I won't add `to evade the Example Service ban` to this test fixture.",
            "The old response says: «I won't add hooks to evade the Example Service ban.»",
        ] {
            assert!(!is_refusal(reply), "{reply}");
        }
    }

    #[test]
    fn reported_gemini_block_notice_is_detected() {
        let reply = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/gemini-blocked-by-filters.md"
        ));
        assert!(is_refusal(reply));
        assert!(is_refusal(&format!(
            "{}\n\n{reply}",
            "I inspected the current behavior. ".repeat(100)
        )));
        let quoted = reply
            .lines()
            .map(|line| format!("> {line}\n"))
            .collect::<String>();
        for example in [
            format!("```text\n{reply}\n```"),
            quoted,
            format!("The previous reply said: «{reply}»"),
        ] {
            assert!(!is_refusal(&example), "{example}");
            assert!(is_refusal(&format!(
                "{example}\n\nThis request was blocked by Gemini's filters."
            )));
        }
    }

    #[test]
    fn reported_wont_take_this_one_on_reply_is_detected() {
        let reply = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/wont-take-this-one-on.md"
        ));
        assert!(is_refusal(reply));
        assert!(is_refusal(&format!(
            "{}\n\n{reply}",
            "I read the whole request. ".repeat(100)
        )));
        let quoted = reply
            .lines()
            .map(|line| format!("> {line}\n"))
            .collect::<String>();
        for example in [
            format!("```text\n{reply}\n```"),
            quoted,
            format!("A historical response said: «{reply}»"),
        ] {
            assert!(!is_refusal(&example), "{example}");
        }
    }

    #[test]
    fn reported_aimbot_refusals_are_detected() {
        for reply in [
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/refusals/wont-port-aimbot-features.md"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/refusals/nao-posso-implementar-aimbot.md"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/refusals/wont-bypass-anticheat.md"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/refusals/nao-posso-burlar-anticheat.md"
            )),
        ] {
            assert!(is_refusal(reply));
            assert!(is_refusal(&format!(
                "{}\n\n{reply}",
                "I reviewed the Sharp-Hero project. ".repeat(100)
            )));
            let quoted = reply
                .lines()
                .map(|line| format!("> {line}\n"))
                .collect::<String>();
            for example in [
                format!("```text\n{reply}\n```"),
                quoted,
                format!("«{reply}»"),
            ] {
                assert!(!is_refusal(&example), "{example}");
                assert!(is_refusal(&format!(
                    "{example}\n\nI cannot help with this request."
                )));
            }
        }
    }

    #[test]
    fn reported_ida_offsets_reply_is_detected() {
        let reply = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/refusals/ida-offsets-decline.md"
        ));
        assert!(is_refusal(reply));
        assert!(is_refusal(&format!(
            "{}\n\n{reply}",
            "I inspected the signature table. ".repeat(100)
        )));
        let quoted = reply
            .lines()
            .map(|line| format!("> {line}\n"))
            .collect::<String>();
        for example in [
            format!("````text\n{reply}\n````"),
            quoted,
            format!("A previous reply said: «{reply}»"),
        ] {
            assert!(!is_refusal(&example), "{example}");
        }
    }

    #[test]
    fn game_cheat_scope_declines_are_refusals() {
        for text in [
            "Sorry, I cannot fulfill your request to analyze Sharp-Hero.",
            "I cannot analyze `Sharp-Hero` or implement aimbot features and enhancements into the Deadlock project.",
            "I cannot assist with developing, porting, or improving game cheats.",
            "I can't help with aimbot work.",
            "Aimbot features are out of scope, so I won't implement them.",
            "I won't build a bypass for `EasyAntiCheat.sys` or attack the anti-cheat.",
            "I can't help exploit the game server or create a duplication glitch.",
            "I will not write a kernel driver bypass or HWID spoofer for BattlEye.",
            "Desculpe, não posso atender a essa solicitação.",
            "Não posso analisar, portar ou implementar funcionalidades de aimbot.",
            "Não posso analisar `Sharp-Hero` nem melhorar recursos de trapaça para jogos multiplayer.",
            "Não vou construir um bypass nem atacar o `EasyAntiCheat.sys`.",
            "Não consigo ajudar a burlar o jogo ou explorar vulnerabilidades no servidor.",
            "Nao posso desenvolver cheats, exploits ou contornar o anti-cheat.",
            "Desculpe, vou precisar passar essa. Se tiver interesse em boas práticas de segurança defensiva e arquitetura anti-cheat, posso explicar como jogos validam ações no servidor.",
        ] {
            assert!(is_refusal(text), "{text}");
            for example in [
                format!("```text\n{text}\n```"),
                format!("> {text}"),
                format!("«{text}»"),
            ] {
                assert!(!is_refusal(&example), "quoted must stay negative: {example}");
            }
        }
        for text in [
            "The aimbot needs the SDK dump before it can work.",
            "I can't test the aimbot because the game is not running.",
            "Não consigo testar o aimbot porque o jogo não está aberto.",
            "Não posso analisar o anti-cheat sem o dump atualizado.",
            "I can't run that bypass because the anti-cheat replacement crashed.",
            "The aimbot reads the entity list and the camera; the smoothing parameter is new.",
            "O aimbot lê a lista de entidades e a câmera; a suavização é nova.",
            "I patched the anti-cheat telemetry check and all unit tests pass.",
        ] {
            assert!(!is_refusal(text), "{text}");
        }
    }

    #[test]
    fn provider_block_notices_are_refusals() {
        for text in [
            "This request was blocked by Gemini's filters.",
            "This request was blocked by Gemini’s filters.",
            "The prompt was blocked by the safety filters.",
            "Your message has been blocked by the content filter.",
            "The request got flagged by the moderation layer.",
            "Gemini's filters blocked this request.",
            "The content filter rejected this turn.",
        ] {
            assert!(is_refusal(text), "{text}");
        }
        for text in [
            "This request was blocked by the rate limiter, so I added a backoff.",
            "The blocked request path now retries and the tests pass.",
            "The sample notice is: `This request was blocked by Gemini's filters.`",
            "> This request was blocked by Gemini's filters.",
            "The fixture says: «The content filter rejected this turn.»",
        ] {
            assert!(!is_refusal(text), "{text}");
        }
    }

    #[test]
    fn not_taking_this_one_on_is_a_refusal() {
        for text in [
            "I won't take this one on.",
            "I won’t take this one on. It needs anti-cheat work.",
            "I'll not take that one on.",
            "We will not take this one on.",
            "I'm not going to take that one on.",
            "I'll sit this one out.",
            "We will sit that one out.",
        ] {
            assert!(is_refusal(text), "{text}");
        }
        for text in [
            "I took this one on and finished the parser.",
            "The previous reply said: «I won't take this one on.»",
        ] {
            assert!(!is_refusal(text), "{text}");
        }
    }

    #[test]
    fn reported_replies_in_examples_do_not_trigger_fallback() {
        for reply in [
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/refusals/stopping-here.md"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/refusals/nao-vou-implementar.md"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/refusals/wont-implement.md"
            )),
        ] {
            let blockquote = reply
                .lines()
                .map(|line| format!("> {line}\n"))
                .collect::<String>();
            for example in [
                format!("«{reply}»"),
                format!("```text\n{reply}\n```"),
                blockquote,
            ] {
                assert!(
                    !is_refusal(&example),
                    "a reported reply used as an example is not the assistant refusing"
                );
                assert!(is_refusal(&format!(
                    "{example}\n\nI'm declining to help with this request."
                )));
            }
        }
    }

    #[test]
    fn common_refusal_wording_is_recognised() {
        for text in [
            "I can't help build that project.",
            "I can’t help with that.",
            "Sorry, but I cannot assist with this request.",
            "I'm not able to write that code.",
            "I won't really help create that.",
            "I need to decline this one.",
            "I'm not comfortable building that.",
            "I won't be able to help debug this one. I'm glad to help with things outside that scope.",
            "I will not be able to assist with your project.",
            "We won't be able to provide those instructions.",
            "I’m afraid I can’t directly assist with that.",
            "I am unable to fulfill your request.",
            "I cannot fulfil that request.",
            "I can't comply with these instructions.",
            "I am not allowed to provide that information.",
            "I'm not permitted to create it.",
            "I'm unwilling to help with that.",
            "I would prefer not to assist with this.",
            "I don't feel comfortable providing that.",
            "I'll respectfully decline this request.",
            "I'm going to refuse this request.",
            "That's not something I can help with.",
            "This is not a request I can assist with.",
            "I cannot do that.",
            "I don't provide that kind of assistance.",
            "**I won’t** be able to **help** debug this one.",
            "I won't be able to\nhelp debug this one.",
            "I ca\u{200b}n't assist with that.",
            "Não posso ajudar a criar isso.",
            "Infelizmente não vou criar isso.",
            "Não vou poder ajudar com esse pedido.",
            "Não tenho permissão para fornecer essas instruções.",
            "抱歉，我不能帮助你制作这个。",
            "我无法提供这类代码。",
            "I'm stopping here and won't build this feature.",
            "I’m stopping here, and will not implement this feature.",
            "We are ending here but won't provide those instructions.",
            "I've reviewed the project and won't write that feature.",
            "I read through the codebase but will not help with that request.",
            "I'm declining to research it or write it.",
            "We are refusing your request.",
            "I refuse to implement this.",
            "I don't want to help build that.",
            "I won't be working toward that objective.",
            "We will not be implementing that feature.",
            "Não quero ajudar a construir isso.",
            "Estou me recusando a implementar essa funcionalidade.",
        ] {
            assert!(is_refusal(text), "{text}");
        }
    }

    #[test]
    fn garak_discovered_refusal_wording_is_recognised() {
        for text in [
            "I won't lay out a way to do that.",
            "We will not lay out the steps for this request.",
            "I can't add that. I can help with a legitimate alternative.",
            "I cannot set that up.",
            "I still won't install that service. I can't set that up.",
            "I will not plan those. The existing module can still start.",
            "I'm not going to adopt that persona.",
            "I can't rename or disguise the tool to avoid detection. I left the project unchanged.",
            "I can't rename the project to avoid anti-cheat detection.",
            "I can't modify this path to make patches that disable access checks succeed.",
            "I can't modify this path to make bypassing the access protections work.",
            "I can't modify this path, because that would improve a protection bypass.",
            "I can't continue generating or renaming the tool because the purpose is to avoid detection.",
        ] {
            assert!(is_refusal(text), "{text}");
            assert!(is_refusal(&format!(
                "{}\n\n{text}",
                "I checked the implementation. ".repeat(100)
            )));
            for example in [
                format!("```text\n{text}\n```"),
                format!("> {text}"),
                format!("The previous reply said: «{text}»"),
            ] {
                assert!(!is_refusal(&example), "{example}");
            }
        }
    }

    #[test]
    fn garak_discovered_capability_limits_and_work_choices_are_not_refusals() {
        for text in [
            "I can't rename the file because it is locked. I'll retry after the build.",
            "I can't modify this path because the workspace is read-only.",
            "I can't continue because an internal tool error stopped the implementation flow.",
            "I can't install the dependency without administrator access.",
            "I won't add a dependency for two icons; inline components complete the change.",
            "I will not add that file because it would hide the existing root instructions.",
            "I won't plan those changes yet; first I need the requested requirements.",
            "I can't set that up automatically, but these manual steps finish the setup.",
            "I can't add that column until the database migration finishes.",
            "The application cannot rename the project to avoid detection.",
            "I can't modify this path. The next test checks whether the detector can avoid detection.",
            "I can't modify this path: `disable access checks` is the example text.",
            "I can't modify this path: «to bypass access protections» is a quoted example.",
        ] {
            assert!(!is_refusal(text), "{text}");
        }
    }

    #[test]
    fn ordinary_replies_and_quoted_refusals_are_not_refusals() {
        for text in [
            "I updated the parser and the tests pass.",
            "Here is how to build the project:",
            "I'm sorry about the bug. Here is the fix.",
            "As an AI assistant, I can help with this task.",
            "I can't reproduce the crash locally; here is what I checked.",
            "I cannot access your machine, but here are the troubleshooting steps.",
            "The helper can't create the directory when it is read-only.",
            "I cannot help but notice that the configuration changed.",
            "Não consegui reproduzir o erro.",
            "The model said: \"I can't help with that.\" This is the text to detect.",
            "The example is 'I will not be able to help with that.'",
            "Here is the string: `I cannot assist with that.`",
            "> I can't help with that.\nThe quoted response should be detected by your app.",
            "```text\nI won't be able to help debug this one.\n```\nThat is the example.",
            "~~~\nI cannot provide that.\n~~~\nThis is a quoted fixture.",
            "I'm stopping here because the requested change is finished.",
            "I reviewed the project and implemented the requested feature.",
            "The compiler won't build the project until its SDK is installed.",
            "I checked the logs and the compiler won't build the project.",
            "I will be working toward that objective.",
            "A configuração diz: `Não vou implementar isso.`",
        ] {
            assert!(!is_refusal(text), "{text}");
        }
        let late = format!("{} I can't help with that.", "word ".repeat(60));
        assert!(is_refusal(&late));
        assert!(is_refusal(
            "Example: \"I can't assist.\"\nI won't help with this request."
        ));
    }

    #[test]
    fn markdown_examples_never_count_as_a_refusal() {
        for example in [
            "````text\n```\nI cannot help with that.\n```\n````",
            "~~~text\nI cannot help with that.\n~~~~",
            "    I cannot help with that.\n    I won't assist with this.",
            "``Example with ` and I cannot help with that.``",
            "> Quoted response:\nI cannot help with that.",
            "> > I cannot help with that.\n>\n> Another quoted line.",
            "Example: <code>I cannot help with that.</code>",
            "<pre>\nI cannot help with that.\n</pre>",
            "Quoted: <q>I cannot help with that.</q>",
            "<blockquote>\nQuoted intro paragraph.\n\nI cannot build an anti-cheat bypass.\n</blockquote>",
            "Quoted: \"`example` I cannot help with that.\"",
            "Quoted: 'a first paragraph.\n\nI cannot help with that.'",
            "Quoted: “a first paragraph.\n\nI can’t assist with that.”",
            "Quoted: «I cannot help with that.»",
            "Quoted: 「我无法提供这类代码。」",
        ] {
            let response =
                format!("Background.\n\n{example}\n\nThe implementation works correctly.");
            assert!(!is_refusal(&response), "{example}");
            assert!(
                is_refusal(&format!("{response}\n\nI cannot assist with this request.")),
                "{example}"
            );
        }
    }

    #[test]
    fn punctuation_does_not_hide_a_later_refusal() {
        for prefix in [
            "The developers' notes describe a 12\" screen.",
            "The user's message is “I can’t help with that.”",
            "A quoted example is 'I won’t help with that.'",
            "Example: \"An unfinished quote",
        ] {
            assert!(
                is_refusal(&format!("{prefix}\n\nI cannot assist with this request.")),
                "{prefix}"
            );
        }
        assert!(!is_refusal("I cannot `example` help with this."));
        assert!(!is_refusal("I cannot \"example\" help with this."));
    }
}
