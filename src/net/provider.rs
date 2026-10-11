pub const NRPT_TAG: &str = "ANTIGRAVITY-BYPASS-RUSSIA";

/// Studio/Gemini canaries. Their substitution results must be checked separately
/// from Cloud Code: a provider can support one family and pass the other through.
pub const SUBSTITUTION_CANARIES: &[&str] = &[
    "aistudio.google.com",
    "makersuite.google.com",
    "generativelanguage.googleapis.com",
    "gemini.google.com",
];

/// Browser AI surfaces (AI Studio, Gemini, NotebookLM, …).
/// These must NOT include Cloud Code, Unleash, OAuth, or www.googleapis.com:
/// those names either passthrough (extra DNS delay) or hang the IDE splash.
pub const NRPT_STUDIO: &[&str] = &[
    ".generativelanguage.googleapis.com",
    "generativelanguage.googleapis.com",
    ".gemini.google.com",
    "gemini.google.com",
    ".gemini.google",
    "gemini.google",
    ".gemini.gstatic.com",
    ".bard.google.com",
    ".generativeai.google",
    ".aistudio.google.com",
    "aistudio.google.com",
    ".ai.studio",
    "ai.studio",
    ".ai.google.dev",
    "ai.google.dev",
    ".makersuite.google.com",
    "makersuite.google.com",
    ".alkalicore-pa.clients6.google.com",
    ".alkalimakersuite-pa.clients6.google.com",
    ".webchannel-alkalimakersuite-pa.clients6.google.com",
    ".alkalimakersuite-pa.googleapis.com",
    ".alkalimakersuiteapplets.pa.googleapis.com",
    ".notebooklm-pa.googleapis.com",
    ".notebooklm.googleapis.com",
    ".notebooklm.google",
    ".notebooklm.google.com",
    ".jules.google",
    ".jules.google.com",
    ".aisandbox-pa.googleapis.com",
    ".deepmind.com",
    ".deepmind.google",
    "deepmind.google",
    ".aiplatform.googleapis.com",
    ".s-aiplatform.googleapis.com",
    ".aicode.googleapis.com",
    "aicode.googleapis.com",
    ".robinfrontend-pa.googleapis.com",
    "robinfrontend-pa.googleapis.com",
    ".webchannel-robinfrontend-pa.googleapis.com",
    "webchannel-robinfrontend-pa.googleapis.com",
    ".proactivebackend-pa.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    ".geller-pa.googleapis.com",
    "geller-pa.googleapis.com",
];

/// Agent Cloud Code, Voice Input & Gemini Desktop App hosts. Each gets its own
/// NRPT nameserver list and fastest TLS-verified SNI proxy pinned in /etc/hosts.
pub const NRPT_AGENT: &[&str] = &[
    "daily-cloudcode-pa.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    "aicode.googleapis.com",
    "robinfrontend-pa.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "geller-pa.googleapis.com",
    "gemini.google.com",
    "alkalimakersuite-pa.clients6.google.com",
    "alkalicore-pa.clients6.google.com",
];

/// Active HTTP/SNI frontends (dns-ai, geohide, etc.). Used when VPN or ISP
/// interferes with UDP DNS: we TLS-probe these with each host SNI and pin the fastest.
pub const GEOHIDE_PROXY_V4: &[&str] = &[
    "191.44.41.79",
    "157.22.177.90",
    "157.22.178.170",
    "193.233.112.67",
    "193.233.112.68",
    "193.233.112.88",
];

pub fn nrpt_domains() -> Vec<&'static str> {
    let mut out = Vec::with_capacity(NRPT_AGENT.len() + NRPT_STUDIO.len());
    out.extend_from_slice(NRPT_AGENT);
    out.extend_from_slice(NRPT_STUDIO);
    out
}
