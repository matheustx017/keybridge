//! Recognizes refusal wording targeting cheats, exploits, aimbots, game tampering,
//! anti-cheats, bypass construction, attacks against anti-cheat or security controls,
//! and the reverse-engineering tooling and binary artifacts used to maintain them.
//!
//! Runs on assistant-owned prose produced by the Markdown/quotation ownership filter:
//! `\u{1}` marks a Markdown block boundary and `\0` marks an omitted quote or inline code.
//! Inline code such as `` `Sharp-Hero` `` or `` `Aimbot.cpp` `` stays inside the same
//! sentence so filenames do not break refusal matching, while quoted refusal text inside
//! backticks or quotes has already been removed.
use std::sync::OnceLock;

use regex::Regex;

/// Evaluates assistant-owned prose for domain-specific refusals (EN, PT, ZH).
pub(super) fn is_refusal(text: &str) -> bool {
    for paragraph in text.split('\u{1}') {
        for sentence in paragraph.split_inclusive(['.', '!', '?']) {
            if sentence_refuses_domain(sentence) {
                return true;
            }
        }
    }
    has_soft_decline_with_defensive_pivot(text)
}

fn sentence_refuses_domain(sentence: &str) -> bool {
    if !domain_target().is_match(sentence) {
        return false;
    }
    if has_direct_stance(sentence) && !blocked_by_operational_limit(sentence) {
        return true;
    }
    if scope_refusal().is_match(sentence) && !third_party_attribution().is_match(sentence) {
        return true;
    }
    false
}

fn has_direct_stance(sentence: &str) -> bool {
    en_stance().is_match(sentence)
        || pt_stance().is_match(sentence)
        || zh_stance().is_match(sentence)
}

/// Returns true when the sentence states a genuine operational/environmental blocker
/// (missing dump, offline server, crashed build, game not running, etc.) rather than
/// a policy or ethical refusal.
fn blocked_by_operational_limit(sentence: &str) -> bool {
    if standalone_operational_limit().is_match(sentence) && !policy_rationale().is_match(sentence) {
        return true;
    }
    let Some(clause) = cause_connector().find(sentence) else {
        return false;
    };
    let reason = &sentence[clause.end()..];
    if policy_rationale().is_match(reason) {
        return false;
    }
    // "until" / "while" already encode a precondition ("until the host is
    // connected"), so the clause itself is the operational limit unless the
    // reason states a policy rationale.
    if waiting_connector().is_match(clause.as_str()) {
        return true;
    }
    causal_operational_limit().is_match(reason)
}

fn waiting_connector() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(r"(?i)^(?:until|while|enquanto|at[eé]\s+que)$")
            .expect("valid waiting connector expression")
    })
}

/// Catches terse or indirect refusals followed by a defensive game-security,
/// anti-cheat architecture, or single-player/offline-only redirect.
fn has_soft_decline_with_defensive_pivot(text: &str) -> bool {
    defensive_redirect().is_match(text) && soft_decline().is_match(text)
}

fn en_stance() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)",
            // First-person inability, unwillingness, permission, discomfort, or decline.
            r"\b(?:i|we)(?:",
            r"\s+(?:can't|cannot|can\s+not|won't|will\s+not|don't|do\s+not)(?:\s+be\s+able\s+to)?",
            r"|(?:'m|'re|\s+am|\s+are)\s+(?:not\s+(?:able|allowed|permitted|willing|going|comfortable)|unable|unwilling)",
            r"(?:\s+to)?",
            r"|(?:'d|\s+would)\s+prefer\s+not\s+to",
            r"|\s+(?:don't|do\s+not)\s+(?:want\s+to|feel\s+comfortable(?:\s+with)?)",
            r"|(?:\s+(?:must|need\s+to|have\s+to|will)|'ll)\s+(?:respectfully\s+)?(?:decline|refuse|pass\s+on|step\s+back\s+from|stop\s+short\s+of)",
            r"|(?:'m|'re|\s+am|\s+are)\s+(?:declining|refusing|passing\s+on|stepping\s+back\s+from)",
            r"|\s+(?:decline|refuse)\s+to",
            r"|\s+draw\s+the\s+line\s+at",
            r"|\s+can\s+[^.!?\x01]{0,180}\bbut\s+(?:(?:i|we)\s+)?(?:not|can't|cannot|won't|will\s+not|refuse\s+to|decline\s+to)",
            r")\b",
            // Optional adverbial hedge + coordinated verb list leading into an action verb.
            r"\s+(?:(?:really|directly|specifically|actually|safely|ethically|responsibly|legally|appropriately|further|in\s+good\s+conscience)\s+){0,2}",
            r"(?:(?:[a-z'’-]+\s*,\s*){0,4}[a-z'’-]+\s+(?:or|nor|and)\s+)?",
            r"(?:help|assist|support|contribute|participate|engage|work\s+on|build|create|construct|write|code|program|develop|implement|design|craft|make|generate|produce|provide|supply|offer|share|give|deliver",
            r"|analy[sz]e|inspect|examine|review|study|research|investigate|explore|probe|hunt\s+for|search\s+for|look\s+for|find|locate|identify|map|trace|diff|dump|extract|decompile|disassemble|reverse(?:[- ]?engineer)?",
            r"|port|adapt|replicate|clone|copy|improve|enhance|extend|expand|upgrade|optimi[sz]e|refine|modify|alter|update|edit|change|refactor|maintain|debug|fix|repair|add|wire|integrate|set\s+up|configure|plan|handle|tackle|pursue|touch|mess\s+with|take\s+on",
            r"|bypass|circumvent|evade|avoid|defeat|disable|neutrali[sz]e|strip|remove|patch|hook|inject|manual[- ]?map|spoof|mask|hide|conceal|obfuscate|disguise|tamper|manipulate|attack|target|exploit|abuse|weaponiz(?:e|ing)|crack|break|weaken|subvert|undermine|automate|override|intercept|emulate|forge|fabricate",
            r"|use|run|operate|launch|start|execute|test|continue|proceed|move\s+forward|go\s+forward|go\s+ahead|explain\s+how\s+to|show\s+(?:you\s+)?how\s+to|guide\s+(?:you\s+)?(?:on|through)|walk\s+(?:you\s+)?through",
            r"|fulfill?|accommodate|honor|honour|grant|do|complete|carry\s+out",
            r"|be\s+(?:helping|assisting|building|creating|writing|developing|implementing|porting|improving|analy[sz]ing|modifying|bypassing|evading|attacking|exploiting|weaponi[sz]ing|reversing|working\s+(?:on|toward))",
            r"|helping|assisting|building|creating|writing|developing|implementing|porting|improving|analy[sz]ing|modifying|bypassing|evading|attacking|exploiting|weaponi[sz]ing|reversing|working\s+on|doing)\b",
        ))
        .expect("valid English domain refusal stance")
    })
}

fn pt_stance() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)",
            // Portuguese modal/habitual/impersonal decline stances (accented and ASCII).
            r"(?:\b(?:eu\s+|n[oó]s\s+)?n[aã]o\s+(?:",
            r"(?:posso|podemos|consigo|conseguimos|vou|vamos|poderei|poderemos|irei|iremos|devo|devemos|quero|queremos|rolo|rola)",
            r"(?:\s+(?:poder|realmente|diretamente|eticamente|legalmente|seguramente|mais))?",
            r"|(?:tenho|temos)\s+permiss[aã]o\s+para",
            r"|(?:estou|estamos)\s+(?:autorizado|autorizados|apto|aptos|disposto|dispostos)\s+a",
            r"|(?:me\s+sinto|nos\s+sentimos|estou|estamos)\s+confort[aá]ve(?:l|is)\s+(?:em|para)",
            r"|[eé]\s+poss[ií]vel",
            r")\s+",
            // Optional clitic object pronouns: "não posso te ajudar", "não vou te ensinar a".
            r"(?:(?:te|lhe|lhes|vos|nos|me)\s+)?",
            r"(?:(?:[a-zà-úçãõéêíôû-]+\s*,\s*){0,4}[a-zà-úçãõéêíôû-]+\s+(?:ou|nem|e)\s+)?",
            r"(?:ajudar|auxiliar|apoiar|suportar|colaborar|contribuir|participar|trabalhar|mexer|criar|construir|desenvolver|implementar|fazer|escrever|programar|gerar|produzir|fornecer|oferecer|compartilhar|entregar|explicar\s+como|mostrar\s+como|ensinar(?:\s+a)?",
            r"|analisar|inspecionar|examinar|revisar|estudar|pesquisar|investigar|explorar|sondar|buscar|procurar|encontrar|localizar|identificar|mapear|rastrear|extrair|descompilar|desmontar|fazer\s+engenharia\s+reversa",
            r"|portar|adaptar|replicar|copiar|melhorar|aprimorar|estender|expandir|otimizar|refinar|modificar|alterar|atualizar|editar|refatorar|manter|depurar|corrigir|reparar|adicionar|integrar|configurar|planejar|lidar|assumir",
            r"|burlar|contornar|driblar|evadir|evitar|derrotar|vencer|desativar|desabilitar|neutralizar|remover|patchear|hookar|ganchar|injetar|mascarar|ocultar|esconder|ofuscar|disfar[cç]ar|simular|falsificar|forjar|adulterar|manipular|atacar|alvejar|abusar|quebrar|crackear|enfraquecer|subverter|automatizar|interceptar|emular",
            r"|usar|rodar|executar|operar|iniciar|testar|continuar|prosseguir|seguir\s+(?:com|adiante)|dar\s+continuidade|atender|cumprir)\b",
            // Portuguese present-habitual policy refusals ("Não desenvolvo cheats", "Não burlo anti-cheat").
            r"|\b(?:eu\s+|n[oó]s\s+)?n[aã]o\s+(?:ajudo|auxilio|apoio|suporto|colaboro|contribuo|participo|trabalho|mexo|crio|construo|desenvolvo|implemento|fa[cç]o|escrevo|gero|produzo|forne[cç]o|ofere[cç]o|presto|realizo|atendo|rolo|rola",
            r"|analiso|estudo|pesquiso|investigo|exploro|porto|adapto|melhoro|aprimoro|modifico|altero|otimizo|reparo|burlo|contorno|evado|desativo|desabilito|neutralizo|ataco|injeto|patcheio|crackeio|quebro|adultero|manipulo|automatizo|ofusco|disfar[cç]o|mascaro|falsifico|forjo)\b",
            // Explicit Portuguese refusal verbs ("Me recuso a...", "Prefiro não...", "Vou recusar...").
            r"|\b(?:(?:eu\s+|n[oó]s\s+)?(?:me\s+recuso|nos\s+recusamos|recuso|recusamos|declino|declinamos)|(?:estou|estamos)\s+(?:me\s+|nos\s+)?(?:recusando|declinando)|(?:preciso|precisamos|devo|devemos|vou|vamos|tenho\s+que|temos\s+que)\s+(?:respeitosamente\s+)?(?:recusar|declinar)|(?:prefiro|preferimos)\s+n[aã]o)\b",
            // Portuguese contrastive partial refusal ("Posso explicar ..., mas não vou/posso ...").
            r"|\bposso\s+[^.!?\x01]{0,180}\bmas\s+n[aã]o\s+(?:posso|vou|consigo|irei|poderei|forne[cç]o|fa[cç]o|desenvolvo|implemento|ajudo|auxilio)\b)",
        ))
        .expect("valid Portuguese domain refusal stance")
    })
}

fn zh_stance() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(r"我(?:不能|无法|不会|没法|没办法|不可以|拒绝|不便|不支持|不提供|不协助|不参与)")
            .expect("valid Chinese domain refusal stance")
    })
}

/// Explicit security/cheat/exploit/anti-cheat/bypass domain targets across EN, PT, and ZH.
fn domain_target() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)",
            // 1. Cheats, aimbots, ESP/wallhacks, and unauthorized game automation/mods (EN & PT).
            r"\b(?:game\s+)?cheat(?:s|ing)?\b",
            r"|\b(?:aimbot|inbot|triggerbot|spinbot|wallhack|speed[- ]?hack|fly[- ]?hack|radar[- ]?hack|teleport[- ]?hack|god[- ]?mode|no[- ]?clip|magic[- ]?bullet|silent[- ]?aim|psilent|auto[- ]?parry|auto[- ]?aim|auto[- ]?fire|auto[- ]?orb|skin[- ]?changer|unlock[- ]?all)s?\b",
            r"|\bno[- ]?recoil\s+(?:cheat|hack|script|macro|feature|mod|function)s?\b",
            r"|\baim[- ]?assist\s+(?:cheat|hack|tool|feature|mod|script)s?\b",
            r"|\b(?:cheat|hack|aimbot|game|player|enemy|wallhack|radar|overlay)\s+(?:[a-zà-úçãõéêíôû'-]+\s+){0,3}esp\b",
            r"|\besp\s+(?:[a-zà-úçãõéêíôû'-]+\s+){0,3}(?:cheat|hack|aimbot|overlay|wallhack|radar|feature|funcionalidade|trapa[cç]a)s?\b",
            r"|\bgame\s+hack(?:s|ing)?\b",
            r"|\bhack(?:s|ing)?\s+(?:de\s+|para\s+)?jogos?\b",
            r"|\btrapa[cç]a(?:s)?\b",
            r"|\b(?:unfair|unauthorized)\s+advantage\b",
            r"|\bvantagem\s+(?:injusta|indevida)\b",
            r"|\bunauthorized\s+(?:game\s+)?(?:mod(?:s|ifications?)?|automation|tools?|clients?|software|scripts?|plugins?)\b",
            r"|\b(?:modifica[cç][aã]o|modifica[cç][oõ]es|automa[cç][aã]o|ferramentas?|scripts?)\s+n[aã]o\s+autorizada(?:s)?\b",
            // 2. Exploits, bug/glitch abuse, packet/memory tampering, and offensive payloads (EN & PT).
            r"|\b(?:game\s+|memory\s+|kernel\s+|driver\s+|client[- ]?side\s+|server[- ]?side\s+|multiplayer\s+|network\s+|packet\s+|zero[- ]?day\s+|0[- ]?day\s+)?exploit(?:s|ation|ing)?\b",
            r"|\bexplora[cç][aã]o\s+de\s+(?:falhas?|vulnerabilidades?|brechas?|bugs?|erros?)\b",
            r"|\bexplorar\s+(?:falhas?|vulnerabilidades?|brechas?|bugs?)\b",
            r"|\b(?:bug|glitch)\s+(?:abuse|exploit(?:s|ing)?)\b",
            r"|\babuso\s+de\s+(?:bug|glitch|falha|mec[aâ]nica)s?\b",
            r"|\b(?:duplication|dupe)\s+(?:glitch|exploit|bug)\b",
            r"|\b(?:packet|memory|client|game|traffic)\s+(?:spoofing|forging|tampering|manipulation|exploitation|hack(?:s|ing)?|cheat(?:s|ing)?)\b",
            r"|\bmanipula[cç][aã]o\s+de\s+(?:pacotes?|mem[oó]ria|tr[aá]fego|jogo|servidor|cliente)\b",
            r"|\badulterar\s+(?:o\s+|os\s+|a\s+|as\s+)?(?:jogo|game|cliente|servidor|mem[oó]ria|pacotes?|tr[aá]fego|anti[- ]?cheat|arquivos?\s+do\s+jogo)\b",
            r"|\btamper(?:ing)?\s+with\s+(?:the\s+|an?\s+)?(?:game|client|server|memory|anti[- ]?cheat|integrity|traffic|packets?|binary|executable)\b",
            r"|\b(?:memory\s+corruption|shellcode|privilege\s+escalation|weaponiz(?:e|ing|ation)|offensive\s+(?:payload|tool|exploit|attack)s?)\b",
            r"|\b(?:server|client)[- ]?side\s+vulnerabilit(?:y|ies)\b",
            r"|\bvulnerabilit(?:y|ies)\s+(?:in|against|of)\s+(?:the\s+|that\s+)?(?:game|server|anti[- ]?cheat|client|service)\b",
            // 3. Anti-cheats, named anti-cheats, anti-tamper, anti-debug, VM/HWID controls.
            r"|\banti[- ]?cheats?\b",
            r"|\banticheats?\b",
            r"|\banti[- ]?tamper\b",
            r"|\banti[- ]?debug(?:ging)?\b",
            r"|\b(?:easy\s*anti[- ]?cheat|battleye|vanguard|ricochet|fairfight|gameguard|xigncode|mqsec|hyperion|byfron|denuvo|nprotect|punkbuster|faceit\s+ac)\b",
            r"|\b(?:vac|eac)\s+(?:bypass(?:es)?|evasion|detection|checks?|bans?|driver|module|anti[- ]?cheat|protection)\b",
            r"|\b(?:bypass(?:ing)?|evad(?:e|ing)|defeat(?:ing)?|disabl(?:e|ing)|attack(?:ing)?|burlar|contornar|evadir|desativar|atacar)\s+(?:o\s+|a\s+)?(?:vac|eac)\b",
            r"|\bhwid\s+(?:spoofer|spoofing|bypass(?:es)?|evasion|ban(?:s)?|changer)\b",
            r"|\bspoofer\s+de\s+hwid\b",
            r"|\bvm[- ]?(?:detection|checks?|rejection)\s*(?:bypass(?:es)?|evasion|avoidance)?\b",
            // 4. Bypass construction, detection evasion, stealth injection, and attacking protections (EN & PT).
            r"|\bbypass(?:es|-backed)?(?:\s|[.,;:!?)\x00]|$)",
            r"|\b(?:evad(?:e|es|ing)|avoid(?:ing)?|defeat(?:ing)?|circumvent(?:ing)?|disabl(?:e|es|ing)|neutrali[sz](?:e|es|ing)|strip(?:ping)?|weaken(?:ing)?|subvert(?:ing)?|undermin(?:e|ing)|attack(?:s|ing)?)\s+(?:(?:the|this|that|a|an|its|their|your|game(?:'s)?|server(?:'s)?|kernel(?:'s)?)\s+){0,3}(?:[a-z'-]+\s+){0,3}(?:detection|anti[- ]?cheat|anticheat|protections?|security(?:\s+(?:checks?|controls?|measures?|mechanisms?|systems?))?|integrity(?:\s+checks?)?|safeguards?|restrictions?|bans?|access\s+controls?|telemetry|checks?|validation|driver|monitoring|signature\s+checks?)\b",
            r"|\b(?:detection|ban|anti[- ]?cheat|security|signature)\s+(?:evasion|avoidance|bypass(?:es)?)\b",
            r"|\b(?:undetected|stealth)\s+(?:cheat|aimbot|esp|hack|loader|injector|driver|mapper|bypass|hook|status)s?\b",
            r"|\b(?:dll|kernel|stealth)\s+(?:injection|injector|mapper)\b",
            r"|\bmanual[- ]?map(?:ping)?\s+(?:a\s+|the\s+)?(?:driver|dll|cheat|module)\b",
            r"|\b(?:burlar|contornar|driblar|evadir|desativar|desabilitar|neutralizar|atacar|derrotar|quebrar|enganar|ludibriar)\s+(?:(?:o|a|os|as|um|uma|esse|este|essa|esta)\s+){0,2}(?:[a-zà-úçãõéêíôû'-]+\s+){0,3}(?:jogo|game|servidor|sistema|anti[- ]?cheat|anticheat|detec[cç][aã]o|seguran[cç]a|prote[cç][aã]o|verifica[cç][aã]o|integridade|ban(?:imento)?|restri[cç][aã]o|controles?|checagens?|driver|telemetria|hwid|valida[cç][aã]o)\b",
            r"|\bataque(?:s)?\s+(?:ao?|contra|em)\s+(?:(?:o|a|um|uma)\s+)?(?:anti[- ]?cheat|anticheat|servidor|jogo|game|seguran[cç]a|prote[cç][aã]o|sistema)\b",
            r"|\bevitar\s+(?:a\s+)?(?:detec[cç][aã]o|ban(?:imento)?|anti[- ]?cheat)\b",
            r"|\bfalsificar\s+(?:hwid|pacotes?|tr[aá]fego|identidade|hardware|telemetria)\b",
            r"|\bindetect[aá]vel\b",
            // 6. Reverse-engineering tooling and the binary artifacts it maintains.
            // A decline to analyze binaries or update signatures/offsets still targets
            // game tampering when it never says "cheat" or "anti-cheat".
            r"|\b(?:ida(?:\s+pro)?|ghidra|x64dbg|binary\s+ninja|radare2|cheat\s+engine|reclass(?:\.net)?|il2cpp\s?dumper|dump(?:er)?[- ]?7)\b",
            r"|\b(?:ida(?:\s+pro)?|ghidra)\s+mcp\b",
            r"|\bmcp\s+(?:do\s+|de\s+|of\s+|from\s+)?(?:ida(?:\s+pro)?|ghidra)\b",
            r"|\b(?:game|compiled|retail|client|target|third[- ]party)\s+(?:binar(?:y|ies)|executables?|images?|builds?)\b",
            r"|\breverse[- ]engineer(?:ing)?\s+(?:(?:of|on|for)\s+)?(?:(?:the\s+|a\s+|an\s+|this\s+|that\s+)?(?:third[- ]party\s+)?)?(?:game\s+)?(?:binar(?:y|ies)|executables?|clients?|builds?|software)\b",
            r"|\b(?:game|memory|binary|module|pattern|struct|vtable)\s+(?:signatures?|offsets?)\b",
            r"|\b(?:signatures?|offsets?|hero\s+names?|nomes?\s+de\s+her[oó]is?)\s*(?:,\s*(?:[a-zà-úçãõéêíôû'-]+\s+){0,2}(?:signatures?|offsets?|hero\s+names?|nomes?\s+de\s+her[oó]is?|names?|nomes?)){0,4}\s*,?\s+(?:and|or|e|ou)\s+(?:(?:the\s+|os?\s+|as?\s+)?(?:broken\s+|quebradas?\s+|missing\s+|stale\s+|memory\s+|game\s+)?)?(?:signatures?|offsets?|hero\s+names?|assinaturas?|nomes?\s+de\s+her[oó]is?)\b",
            r"|\b(?:signatures?|offsets?)\s+(?:and|or|,)\s+(?:signatures?|offsets?)\b",
            r"|\b(?:recover|resolve|maintain|update|fix|repair|extract|reparar|extrair|atualizar|corrigir)\s+(?:(?:the\s+|os?\s+|as?\s+)?(?:broken\s+|quebradas?\s+|missing\s+|stale\s+)?)?(?:offsets?|signatures?|assinaturas?|signature\s+scan|signature\s+scans)\b",
            r"|\b(?:extract|repair|fix|update|reparar|extrair)\s+or\s+(?:extract|repair|fix|update|reparar|extrair)\s+(?:(?:the\s+|os?\s+|as?\s+)?(?:broken\s+|quebradas?\s+)?)?(?:signatures?|offsets?|assinaturas?)\b",
            r"|\bmemory[- ](?:injection|manipulation)\b",
            r"|\b(?:manipula[cç][aã]o|adultera[cç][aã]o)\s+de\s+mem[oó]ria\b",
            r"|\b(?:bin[aá]rios?|execut[aá]veis?)\s+(?:compilados?|do\s+jogo|de\s+terceiros?)\b",
            r"|\b(?:assinaturas?|offsets?)\s+(?:de\s+)?(?:mem[oó]ria|bin[aá]rio|m[oó]dulo)\b",
            r"|\binje[cç][aã]o\s+de\s+mem[oó]ria\b",
            // 7. Chinese game-cheat / exploit / anti-cheat / bypass terms.
            r"|(?:外挂|作弊|自瞄|透视|锁头|无后座|穿墙|加速挂|绕过|反作弊|过检测|漏洞利用|攻击反作弊|内存修改|注入器|驱动绕过)",
        ))
        .expect("valid domain target expression")
    })
}

/// Third-person / topic-subject scope declines without requiring a first-person modal.
fn scope_refusal() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)",
            r"\b(?:is|are)\s+(?:(?:clearly|strictly|firmly)\s+)?(?:out\s+of\s+scope|off[- ]?limits|prohibited|not\s+allowed|not\s+permitted",
            r"|not\s+something\s+(?:i|we)\s+(?:can|will)\b",
            r"|something\s+(?:i|we)\s+(?:can't|cannot|can\s+not|won't|will\s+not|refuse\s+to|decline\s+to)\b",
            r"|(?:outside|beyond)\s+(?:what\s+(?:i|we)\s+can|my\s+scope|our\s+scope|my\s+guidelines|our\s+guidelines))",
            r"|\b(?:(?:is|are)\s+against|goes?\s+against|violates?|conflicts?\s+with|crosses)\s+(?:(?:my|our|the)\s+)?(?:safety\s+|usage\s+|ethical\s+)?(?:guidelines?|polic(?:y|ies)|rules?|boundaries|principles?)\b",
            r"|\b(?:est[aá]|est[aã]o)\s+fora\s+(?:do\s+(?:meu\s+|nosso\s+)?escopo|das?\s+(?:minhas?\s+|nossas?\s+)?(?:diretrizes?|pol[ií]ticas?|limites?))\b",
            r"|\bn[aã]o\s+[eé]\s+(?:algo\s+(?:em\s+que\s+|que\s+)?(?:eu\s+|n[oó]s\s+)?(?:posso|possa|consigo|consiga|vou|vamos)|permitido|autorizado)\b",
            r"|\b(?:vai|v[aã]o)\s+contra\s+(?:as?\s+)?(?:minhas?\s+|nossas?\s+)?(?:diretrizes?|pol[ií]ticas?|regras?|princ[ií]pios?)\b",
            r"|\bviola(?:m)?\s+(?:as?\s+)?(?:minhas?\s+|nossas?\s+)?(?:diretrizes?|pol[ií]ticas?|regras?)\b",
        ))
        .expect("valid scope refusal expression")
    })
}

/// Prevents third-party policy/doc summaries ("Your skill lists anti-cheat bypass as out of scope")
/// from triggering `scope_refusal`.
fn third_party_attribution() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)\b(?:the|this|that|your)\s+(?:project(?:'s)?\s+(?:own\s+)?)?",
            r"(?:skill|doc(?:ument(?:ation)?)?|spec|readme|rule|policy\s+file|config|guide|report|log|comment|test|scanner|application|client|game|server)\b",
            r"[^.!?\x01]{0,80}\b(?:lists?|marks?|states?|says?|mentions?|notes?|defines?|treats?|describes?|diz|lista|marca|define|indica)\b",
        ))
        .expect("valid third-party attribution expression")
    })
}

fn cause_connector() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:because|due\s+to|since|until|while|without|porque|pois|enquanto|sem|at[eé]\s+que|antes\s+que)\b",
        )
        .expect("valid cause connector expression")
    })
}

/// Unconditional environmental/session blockers that indicate a capability limit even
/// without an explicit `because`/`porque` clause ("I can't run that bypass from here").
fn standalone_operational_limit() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)\b(?:",
            r"from\s+(?:here|this\s+session|this\s+environment)",
            r"|in\s+this\s+(?:session|environment|sandbox)",
            r"|(?:nesta|desta)\s+sess[aã]o",
            r"|neste\s+ambiente",
            r"|without\s+(?:(?:the|an?|this|that|your|my)\s+)?(?:[a-z'-]+\s+){0,2}(?:logs?|dumps?|sdk|symbols?|binar(?:y|ies)|pdb|access|admin(?:istrator)?\s+(?:rights?|access|privileges?)|host\s+access|database|running\s+game|live\s+process)",
            r"|sem\s+(?:(?:o|os|a|as|um|uma)\s+)?(?:[a-zà-úçãõéêíôû'-]+\s+){0,2}(?:logs?|dumps?|sdk|s[ií]mbolos?|bin[aá]rios?|pdb|acesso|privil[eé]gios?\s+de\s+administrador|jogo\s+aberto|processo\s+ativo)",
            r")\b",
        ))
        .expect("valid standalone operational limit expression")
    })
}

/// Operational/technical causes inside a `because`/`until`/`while`/`porque`/`sem` clause.
fn causal_operational_limit() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)\b(?:",
            r"crash(?:ed|es|ing)?|missing|unavailable|offline|read[- ]?only|locked|expired|timed?\s+out|permission\s+denied",
            r"|not\s+(?:running|open|installed|connected|loaded|attached|built|compiled|found|present|available|exposed|part\s+of)",
            r"|no\s+(?:host\s+)?access|(?:don't|do\s+not)\s+have\s+(?:host\s+)?access|no\s+display|no\s+(?:dump|sdk|log|logs|symbols?|binary)",
            r"|tool\s+error|internal\s+(?:tool\s+)?error|ci\s+is\s+(?:down|offline|back)|build\s+(?:failed|is\s+broken)",
            // Positive readiness after until/while is handled by waiting_connector;
            // keep only waiting/already-done markers for because/since/sem clauses.
            r"|waiting\s+for|already\s+(?:works?|working|fixed|finished|complete|done)",
            r"|fora\s+do\s+ar|indispon[ií]vel|somente\s+leitura|bloquead[oa]|travad[oa]|crashou|falhou|faltando|ausente|expirou",
            r"|n[aã]o\s+est[aá]\s+(?:rodando|aberto|aberta|instalad[oa]|conectad[oa]|carregad[oa]|dispon[ií]vel|expost[oa]|em\s+execu[cç][aã]o)",
            r"|n[aã]o\s+(?:tenho|temos)\s+acesso|erro\s+interno|erro\s+de\s+ferramenta|j[aá]\s+funciona",
            r"|o\s+(?:log|dump|sdk|bin[aá]rio|arquivo|reposit[oó]rio|banco|servidor\s+local)\b",
            r")\b",
        ))
        .expect("valid causal operational limit expression")
    })
}

/// Explicit ethical/policy rationales that override operational-looking wording.
/// Plain technical nouns ("anti-cheat", "bypass") stay excluded here so phrases like
/// "because the anti-cheat replacement crashed" remain operational limits.
fn policy_rationale() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)\b(?:",
            r"(?:my|our)\s+(?:safety\s+|ethical\s+|usage\s+)?(?:guidelines?|polic(?:y|ies)|rules?|boundaries|principles?)",
            r"|(?:minhas?|nossas?)\s+(?:diretrizes?|pol[ií]ticas?|regras?|limites?|princ[ií]pios?)",
            r"|unfair\s+advantage|vantagem\s+(?:injusta|indevida)",
            r"|hurts?\s+other\s+(?:real\s+)?players|prejudica\s+(?:diretamente\s+)?(?:outros\s+jogadores|quem\s+est[aá])",
            r"|probing\s+a\s+third\s+party",
            r")\b",
        ))
        .expect("valid policy rationale expression")
    })
}

fn soft_decline() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)\b(?:",
            r"sorry|apologize|apologies|unfortunately|desculpe|sinto\s+muito|infelizmente",
            r"|(?:i|we)(?:'ll|\s+will|\s+have\s+to|\s+must|\s+need\s+to|'m\s+going\s+to)\s+(?:skip|pass\s+on|step\s+back|stop\s+here)",
            r"|(?:vou|vamos|preciso|devo|tenho\s+que)\s+(?:passar|pular|parar\s+por\s+aqui)",
            r"|(?:i|we)\s+(?:haven't|have\s+not|didn't|did\s+not)\s+(?:changed?|modified?|edited?|touched?|created?|set\s+up|started?|run|launched?)",
            r"|made\s+no\s+(?:code\s+|file\s+)?changes|left\s+the\s+(?:project|codebase|files?|workspace)\s+unchanged",
            r"|n[aã]o\s+(?:mexi|alterei|modifiquei|criei|iniciei|fiz\s+altera[cç][oõ]es|vou\s+mexer|posso\s+seguir)",
            r")\b",
        ))
        .expect("valid soft decline expression")
    })
}

fn defensive_redirect() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)\b(?:",
            r"if\s+you(?:'re|\s+are)\s+interested\s+in\s+(?:[^.!?\x01]{0,100})(?:defensive\s+(?:game\s+|security\s+)?(?:security|engineering)|software\s+security|game\s+security|anti[- ]?cheat\s+(?:engineering|architecture|design|systems?)|legitimate\s+(?:gameplay|binary\s+analysis)|C\+\+\s+engineering|standard\s+software\s+development)",
            r"|defensive\s+(?:game\s+)?(?:security\s+practices|engineering|security)",
            r"|defensive\s+security\s+engineering",
            r"|software\s+security",
            r"|legitimate\s+binary\s+analysis",
            r"|C\+\+\s+engineering\s+best\s+practices",
            r"|standard\s+software\s+development\s+resources",
            r"|search\s+(?:online\s+)?for\s+(?:[^.!?\x01]{0,80})(?:security\s+best\s+practices|defensive\s+(?:engineering|security)|standard\s+software\s+development|C\+\+\s+engineering)",
            r"|if\s+this\s+were\s+for\s+(?:a\s+game\s+you\s+own|an?\s+(?:offline|private|single[- ]?player))",
            r"|(?:i|we)\s+can\s+(?:still\s+)?(?:help|assist)\s+with\s+(?:[^.!?\x01]{0,80})(?:defensive|legitimate|single[- ]?player|offline\s+(?:game|build|server)|your\s+own\s+(?:game|project)|anti[- ]?cheat\s+(?:design|architecture|engineering))",
            r"|se\s+tiver\s+interesse\s+em\s+(?:[^.!?\x01]{0,100})(?:boas\s+pr[aá]ticas\s+de\s+seguran[cç]a|seguran[cç]a\s+(?:defensiva|de\s+software)|engenharia\s+defensiva|arquitetura\s+anti[- ]?cheat|prote[cç][aã]o\s+de\s+(?:aplica[cç][oõ]es\s+e\s+)?jogos|an[aá]lise\s+bin[aá]ria\s+leg[ií]tima|engenharia\s+C\+\+|boas\s+pr[aá]ticas\s+de\s+engenharia)",
            r"|seguran[cç]a\s+de\s+software|engenharia\s+defensiva",
            r"|an[aá]lise\s+bin[aá]ria\s+leg[ií]tima",
            r"|engenharia\s+de\s+seguran[cç]a\s+defensiva\s+e\s+arquitetura\s+anti[- ]?cheat",
            r"|posso\s+(?:ainda\s+)?ajudar\s+com\s+(?:[^.!?\x01]{0,80})(?:seguran[cç]a\s+defensiva|single[- ]?player|offline|jogos\s+pr[oó]prios|do\s+ponto\s+de\s+vista\s+de\s+quem\s+(?:desenvolve|protege))",
            r")\b",
        ))
        .expect("valid defensive redirect expression")
    })
}

#[cfg(test)]
mod tests {
    use super::is_refusal;

    #[test]
    fn covers_all_cheat_aimbot_exploit_anticheat_bypass_and_attack_refusals_en_pt_zh() {
        for text in [
            // Aimbot & game cheats (EN)
            "I cannot analyze \0 or implement aimbot features and enhancements into the Deadlock project.",
            "I can't port aimbot or ESP features from another cheat.",
            "I won't improve, optimize, or maintain game cheats for online multiplayer matches.",
            "I am unable to reverse-engineer the game to add wallhack or triggerbot logic.",
            "We don't build silent aim, magic bullet, or speedhack features.",
            "I'm not going to inspect \0 to replicate its auto-parry or auto-orb cheat.",
            "Aimbot features are out of scope.",
            "Developing game cheats for online games violates my guidelines.",
            "Building unauthorized automation tools for online games is not something I can do.",
            // Exploits & game tampering (EN)
            "I cannot write, test, or refine a server-side exploit for that game.",
            "I won't search for duplication glitches or bug abuse in multiplayer servers.",
            "I can't craft packet forging or memory tampering code for the game client.",
            "I will not weaponize that vulnerability or build an exploit payload.",
            "Exploiting vulnerabilities in online game servers is off-limits.",
            // Anti-cheats, bypass construction & attacking anti-cheats (EN)
            "I cannot build, port, or improve an anti-cheat bypass.",
            "I won't help construct a kernel driver bypass for Easy Anti-Cheat or BattlEye.",
            "I can't reverse engineer Vanguard to disable or neutralize its integrity checks.",
            "I will not attack the anti-cheat or patch out its detection routines.",
            "I am not able to create an HWID spoofer or evade VAC bans.",
            "I cannot obfuscate or disguise this loader to make it an undetected cheat.",
            "I'm unwilling to write a stealth injector or manual-map a cheat driver to bypass EAC.",
            "I can explain how anti-cheat telemetry works, but I won't bypass anti-cheat checks.",
            "Attacking anti-cheat systems is against my policies.",
            "Bypassing MQSec or Hyperion detection is outside what I can assist with.",
            "I draw the line at helping with game cheats.",
            "I can't reverse EasyAntiCheat.sys to strip its checks.",
            "I'm sorry, but I can't help you bypass EasyAntiCheat.",
            "I won't show you how to make the cheat undetected.",
            // Aimbot & game cheats (PT - accented & unaccented)
            "Não posso analisar, portar ou implementar funcionalidades de aimbot ou outras ferramentas de trapaça para jogos multiplayer.",
            "Nao posso melhorar ou adaptar esse aimbot nem recursos de wallhack para o jogo.",
            "Não vou mexer em \0 para adicionar triggerbot ou silent aim.",
            "Não desenvolvo cheats nem automação não autorizada para jogos online.",
            "Funcionalidades de aimbot e trapaça estão fora do meu escopo.",
            "Desculpe, não posso te ajudar a fazer cheat.",
            "Não vou te ensinar a fazer aimbot.",
            "Não rolo ajudar com hacks de jogos.",
            "Me recuso a ajudar com trapaças para jogos online.",
            // Exploits & burlar games (PT)
            "Não posso explorar falhas ou vulnerabilidades no servidor do jogo.",
            "Não vou criar um exploit nem ajudar no abuso de bugs em partidas online.",
            "Não consigo ajudar a burlar o jogo ou adulterar pacotes do servidor.",
            "Não posso te ajudar a burlar o jogo.",
            "Nao posso manipular a memoria do jogo para obter vantagem injusta.",
            "Explorar brechas em jogos multiplayer viola minhas diretrizes.",
            "Adulterar pacotes do jogo viola minhas regras.",
            // Anti-cheats, construir bypass & atacar anti-cheats (PT)
            "Não posso construir um bypass para o Easy Anti-Cheat ou BattlEye.",
            "Não vou ajudar a burlar, contornar ou desativar o anti-cheat.",
            "Não vou te ensinar a burlar o anti-cheat.",
            "Não consigo participar de ataques ao anti-cheat nem neutralizar suas verificações.",
            "Não faço engenharia reversa de anti-cheat para criar um bypass ou spoofer de HWID.",
            "Não é possível desenvolver um bypass de detecção ou deixar o loader indetectável.",
            "Posso explicar arquitetura defensiva, mas não vou contornar o anti-cheat.",
            "Construir bypass ou atacar anti-cheats não é algo em que eu possa ajudar.",
            "Atacar sistemas anti-cheat vai contra as minhas diretrizes.",
            "Me recuso a construir bypass para o Easy Anti-Cheat.",
            "Atacar o BattlEye ou desativar detecção está fora do meu escopo.",
            // Reverse-engineering tooling and binary artifacts (EN)
            "I cannot use IDA Pro to analyze compiled game binaries, update memory signatures or offsets, or fix and improve game cheat software.",
            "I cannot use IDA Pro to analyze compiled game binaries.",
            "I can't update the memory signatures or offsets for that build.",
            "I won't reverse-engineer the compiled binaries to recover the offsets.",
            "We cannot diff the two client builds in Ghidra.",
            "I'm unable to maintain the signature scans for this anti-cheat module.",
            "I am unable to assist with reverse-engineering third-party game binaries to extract or repair signatures and offsets.",
            "I won't repair broken signatures, hero names, or offsets.",
            "I won't update hero names or repair the offsets.",
            "I cannot help with IDA MCP analysis of signatures, hero names, and offsets.",
            "I can't assist with memory-manipulation tools or triggerbots.",
            "We will not extract or repair signatures and offsets from the game client.",
            "I'm not able to reverse-engineer third-party game binaries.",
            // Reverse-engineering tooling and binary artifacts (PT)
            "Não posso analisar os binários compilados do jogo no IDA para atualizar offsets.",
            "Não consigo manter as assinaturas de memória do módulo.",
            "Não vou reparar assinaturas, nomes de heróis ou offsets quebrados.",
            "Não posso usar o MCP do IDA para analisar assinaturas e offsets.",
            "Não consigo ajudar com ferramentas de manipulação de memória ou triggerbots.",
            // Subtle decline + defensive redirect (EN & PT)
            "Desculpe, vou precisar passar essa. Se tiver interesse em boas práticas de segurança defensiva e arquitetura anti-cheat, posso ajudar.",
            "Sorry, I'll have to skip this one. If you are interested in game security, anti-cheat engineering, or legitimate gameplay mechanics for your own projects, you can search online for defensive game security practices.",
            "Sorry, I'll have to skip this one. If you are interested in legitimate binary analysis or C++ engineering best practices, you can search for standard software development resources online.",
            "Desculpe, não vou mexer nisso. Se tiver interesse em segurança de software ou engenharia defensiva, posso explicar o assunto.",
            "Desculpe, vou passar. Se tiver interesse em análise binária legítima ou boas práticas de engenharia C++, posso apontar material.",
            // Policy reason inside a because/porque clause
            "I can't test that bypass because it evades anti-cheat detection in live online multiplayer games.",
            "Não posso testar esse bypass porque ele contorna o anti-cheat em jogos online.",
            // Chinese
            "我不能帮你编写游戏外挂或自瞄功能。",
            "我无法提供绕过反作弊系统的方案。",
            "我拒绝协助开发漏洞利用或攻击反作弊驱动。",
        ] {
            assert!(is_refusal(text), "expected refusal: {text}");
        }
    }

    #[test]
    fn preserves_operational_limits_technical_prose_and_third_party_summaries() {
        for text in [
            // Operational limits (EN & PT)
            "I can't test the aimbot because the game is not running.",
            "I can't run that bypass because it crashed.",
            "I can't run that bypass until the host is connected.",
            "I can't run that bypass from here.",
            "I can't search for vulnerabilities while the local test environment is offline.",
            "I can't analyze the anti-cheat dump without the updated symbols.",
            "I won't modify \0 yet until you confirm the offset.",
            "Não consigo testar o aimbot porque o jogo não está aberto.",
            "Não posso analisar o anti-cheat sem o dump atualizado.",
            "Não consigo rodar o bypass porque o processo crashou.",
            "Não posso testar o exploit enquanto o servidor local estiver offline.",
            "Não posso mexer no aimbot porque o workspace é somente leitura.",
            // Non-refusal technical descriptions & completed work
            "The aimbot needs the SDK dump before it can work.",
            "The aimbot reads the entity list and the camera; the smoothing parameter is new.",
            "O aimbot lê a lista de entidades e a câmera; a suavização é nova.",
            "I can't run a bypass-free example.",
            "The application cannot rename the project to avoid detection.",
            "The scanner won't search for vulnerabilities without its test database.",
            "I fixed the aimbot smoothing bug and verified the anti-cheat telemetry test.",
            "I did not modify \0 because the bug was in the renderer.",
            "Your project's own skill lists anti-cheat bypass as out of scope.",
            "The report mentions a server-side exploit; I fixed the validation issue.",
            "I can't modify this path. The next test checks whether the detector can avoid detection.",
            "Here is how defensive game security practices and anti-cheat engineering protect server authority.",
            "I made no code changes; here is the summary of the crash trace.",
            "I can't test that bypass because the anti-cheat replacement crashed.",
            "Não posso rodar esse bypass porque o anti-cheat crashou.",
            // Technical prose about tooling and offsets without a domain stance
            "The IDA output lists the new offsets.",
            "I updated the memory signatures and the build passes.",
            "The module's signature scan found nothing.",
            "I can't run IDA because the license expired.",
            "Não consegui atualizar os offsets porque a ferramenta expirou.",
        ] {
            assert!(!is_refusal(text), "unexpected refusal: {text}");
        }
    }
}
