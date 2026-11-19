//! Links operational and past-tense declines to their policy reason in owned prose.
use std::sync::OnceLock;

use regex::Regex;

const EN_ACTION: &str = r"(?:operate|run|launch|start|execute|use|test|continue|proceed|click|modify|patch|hook|inject|port|attach|analyze|analyse)";
const PT_ACTION: &str = r"(?:operar|rodar|executar|iniciar|abrir|usar|testar|continuar|prosseguir|clicar|modificar|alterar|patchear|injetar|portar|analisar|mexer)";
const CONTROL: &str = concat!(
    r"(?:anti[- ]?cheat(?:s)?|anticheat(?:s)?|anti[- ]?tamper|anti[- ]?debug(?:ging)?",
    r"|VM[- ](?:detection|checks?|rejection)",
    r"|security\s+(?:controls?|protections?|checks?)",
    r"|integrity\s+(?:checks?|verification)",
    r"|hwid\s+(?:spoofer|spoofing|ban|bypass)",
    r"|detection\s+(?:evasion|avoidance|bypass)",
    r"|game\s+cheats?|aimbot(?:s)?|wallhack(?:s)?|trapa[cç]a(?:s)?|ferramentas?\s+de\s+trapa[cç]a",
    r"|controles?\s+de\s+seguran[cç]a|prote[cç][oõ]es?\s+de\s+seguran[cç]a|detec[cç][aã]o\s+de\s+vm)",
);

/// Paragraph/code/quotation boundaries come from the Markdown ownership filter.
/// Split on `\u{1}` (Markdown block boundary) so inline code filenames (`\0`) inside
/// a sentence do not sever the decline from its policy reason; `\0` inside a phrase
/// still breaks the whitespace match so omitted spans cannot bridge words.
pub(super) fn is_refusal(text: &str) -> bool {
    for paragraph in text.split('\u{1}') {
        let reasons: Vec<_> = reason().find_iter(paragraph).collect();
        let mut sentence_offset = 0;
        for sentence in paragraph.split_inclusive(['.', '!', '?']) {
            if !operational_limit().is_match(sentence) {
                for decline in decline().captures_iter(sentence) {
                    let matched = decline.get(0).expect("complete decline match");
                    let tail = &sentence[matched.end()..];
                    let direct = decline.name("direct").is_some();

                    // A stated operational cause must not inherit a policy reason
                    // from elsewhere: "can't run that path because it crashed".
                    if let Some(cause) = cause().find(tail) {
                        if reason().is_match(&tail[cause.end()..]) {
                            return true;
                        }
                        continue;
                    }
                    if direct && bypass_object().is_match(tail) {
                        return true;
                    }

                    let position = sentence_offset + matched.start();
                    let Some(prior) = reasons.iter().rev().find(|reason| reason.end() <= position)
                    else {
                        continue;
                    };
                    let between = &paragraph[prior.end()..position];
                    if operational_limit().is_match(&paragraph[prior.start()..position]) {
                        continue;
                    }
                    // "The route uses a replacement, so I stopped before using it."
                    // "That path" may refer to the preceding sentence, but never
                    // to a reason in another paragraph or an omitted quotation.
                    if consequence().is_match(between)
                        || (direct && referenced_path().is_match(tail))
                    {
                        return true;
                    }
                }
            }
            sentence_offset += sentence.len();
        }
    }
    false
}

fn decline() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| Regex::new(&format!(concat!(
        r"(?i)\b(?:(?P<direct>",
        r"(?:i|we)(?:\s+(?:can't|cannot|can\s+not|won't|will\s+not)|(?:'m|'re|\s+am|\s+are)\s+(?:not\s+going|unable|unwilling)\s+to)\s+{en_action}",
        r"|(?:i|we)\s+can\s+[^.!?\x01]{{0,240}}\bbut\s+(?:(?:i|we)\s+)?(?:not|can't|cannot|won't|will\s+not)\s+{en_action}",
        r"|(?:eu\s+|n[oó]s\s+)?n[aã]o\s+(?:posso|podemos|consigo|conseguimos|vou|vamos|irei|poderei)\s+{pt_action}",
        r"|posso\s+[^.!?\x01]{{0,240}}\bmas\s+n[aã]o\s+(?:posso|vou|consigo|irei|poderei)?\s*{pt_action})",
        r"|(?:i|we)\s+(?:(?:did\s+not|didn't|have\s+not|haven't)\s+(?:start(?:ed)?|launch(?:ed)?|run|use(?:d)?|execut(?:e|ed)|continu(?:e|ed)|proceed(?:ed)?|click(?:ed)?|modif(?:y|ied)|chang(?:e|ed)|patch(?:ed)?|add(?:ed)?|creat(?:e|ed)|set\s+up)",
        r"|(?:stopped|paused|halted)\s+(?:before|prior\s+to|short\s+of|without)\s+(?:starting|launching|running|using|operating|executing|continuing|proceeding|modifying|patching))",
        r"|(?:eu\s+|n[oó]s\s+)?(?:n[aã]o\s+(?:iniciei|iniciamos|rodei|rodamos|executei|executamos|abri|abrimos|usei|usamos|continuei|prossegui|alterei|modifiquei|criei|configurei|adicionei)",
        r"|(?:parei|paramos|interrompi|interrompemos)\s+(?:antes\s+de|sem)\s+(?:iniciar|rodar|executar|abrir|usar|operar|continuar|prosseguir|alterar|modificar)))\b"
    ), en_action = EN_ACTION, pt_action = PT_ACTION)).expect("valid policy decline expression"))
}

fn reason() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| Regex::new(&format!(concat!(
        r"(?i)\b(?:",
        r"(?:uses?|requires?|(?:rel(?:y|ies)|depends?)\s+on|involves?|targets?|is\s+(?:a|an))\s+(?:(?:an?|the)\s+)?{control}(?:\s+(?:replacements?|bypass(?:es)?|evasion|attacks?|tools?|features?|for\s+(?:an?\s+)?(?:online|multiplayer|pvp)\s+games?))?",
        r"|(?:bypass(?:es|ing)?|evad(?:e|es|ing)|replac(?:e|es|ing)|disabl(?:e|es|ing)|defeat(?:s|ing)?|attack(?:s|ing)?|circumvent(?:s|ing)?|neutrali[sz](?:e|es|ing))\s+(?:[a-z'-]+\s+){{0,4}}{control}",
        r"|(?:usa|utiliza|requer|depende\s+de|envolve|[eé]\s+(?:um|uma))\s+(?:(?:um|uma|o|a)\s+)?(?:bypass(?:es)?\s+(?:de|do|da|para)\s+)?{control}(?:\s+(?:para\s+jogos?\s+(?:online|multiplayer|pvp|competitivos?)))?",
        r"|(?:burla(?:r|ndo)?|contorna(?:r|ndo)?|evad(?:e|ir|indo)|desativa(?:r|ndo)?|desabilita(?:r|ndo)?|substitu(?:i|ir|indo)|ataca(?:r|ndo)?)\s+(?:[a-zà-úçãõéêíôû'-]+\s+){{0,4}}{control}",
        r")\b"
    ), control = CONTROL)).expect("valid policy reason expression"))
}

fn bypass_object() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| Regex::new(&format!(
        r"(?i)^\s+(?:(?:this|that|the|an?|these|those|its|your|esse|este|essa|esta|o|a|um|uma)\s+)?(?:bypass(?:es|-backed)?|{control}\s+(?:replacements?|bypass(?:es)?))(?:\s|[.,;:!?]|$)",
        control = CONTROL,
    )).expect("valid declined object expression"))
}

fn referenced_path() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(
            r"(?i)^\s+(?:it|isso|(?:this|that|esse|este|essa|esta)\s+(?:path|route|setup|configuration|launch|run|caminho|rota|configura[cç][aã]o|execu[cç][aã]o|projeto|recurso|funcionalidade))\b",
        )
        .expect("valid path reference expression")
    })
}

fn cause() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:because|due\s+to|since|until|while|without|porque|pois|devido\s+a|j[aá]\s+que|visto\s+que|enquanto|sem|at[eé]\s+que)\b")
            .expect("valid cause expression")
    })
}

fn consequence() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:so|therefore|thus|which\s+is\s+why|that's\s+why|ent[aã]o|portanto|por\s+isso|logo|pelo\s+mesmo\s+motivo)\b")
            .expect("valid consequence expression")
    })
}

fn operational_limit() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| Regex::new(concat!(
        r"(?i)\b(?:crash(?:ed|es)?|missing|unavailable|not\s+installed|not\s+connected|not\s+running|permission\s+denied|timed?\s+out|",
        r"no\s+(?:host\s+)?access|(?:don't|do\s+not)\s+have\s+(?:host\s+)?access|no\s+display|from\s+(?:here|this\s+session)|",
        r"crashou|faltando|ausente|indispon[ií]vel|n[aã]o\s+est[aá]\s+(?:instalad[oa]|conectad[oa]|rodando|aberto)|sem\s+acesso|(?:nesta|desta)\s+sess[aã]o)\b"
    )).expect("valid operational limit expression"))
}

#[cfg(test)]
mod tests {
    use super::is_refusal;

    #[test]
    fn operational_objects_and_references_require_a_policy_decline() {
        for text in [
            "I can't operate that bypass to run the protected client.",
            "I can help debug the renderer, but not run that bypass against the authenticated game.",
            "The route relies on an anti-cheat replacement. I can analyze the evidence, but I can't operate that path.",
            "The route depends on an anti-cheat replacement, so I stopped before using it.",
            "I stopped before launching because the route relies on an anti-cheat replacement and a modified guest environment.",
            // Portuguese operational/past-tense policy declines
            "Não iniciei a execução porque a rota depende de um bypass de anti-cheat.",
            "O caminho depende de um bypass de anti-cheat, então parei antes de rodar.",
            "Posso ajudar com a renderização, mas não vou executar esse bypass.",
            "O projeto é uma ferramenta de trapaça para jogos online, por isso não alterei os arquivos.",
            "Não criei o \0 porque o projeto envolve um bypass de anti-cheat.",
            "I did not modify \0 because the route relies on an anti-cheat bypass.",
        ] {
            assert!(is_refusal(text), "{text}");
        }
        for text in [
            "I can't operate that path.",
            "I can't operate that bypass because it crashed.",
            "I can't run that bypass until the host is connected.",
            "I can't run that bypass from here.",
            "I can't run a bypass-free example.",
            "I did not run the bypass. The normal launch worked.",
            "The route uses an anti-cheat replacement. I can't operate that path because the file is locked.",
            "The route relies on an anti-cheat replacement.\u{1}I can't operate that path.",
            "The route relies on\0 an anti-cheat replacement. I can't operate that path.",
            "The route uses an anti-cheat replacement that crashed, so I stopped before using it.",
            "I saved the traces and found no demonstrated rendering defect to patch.",
            "Não rodei esse bypass porque o processo crashou.",
            "Não iniciei a rota porque o anti-cheat está faltando.",
        ] {
            assert!(!is_refusal(text), "{text}");
        }
    }
}
